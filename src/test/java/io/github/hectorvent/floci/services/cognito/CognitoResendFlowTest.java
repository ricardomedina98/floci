package io.github.hectorvent.floci.services.cognito;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cognito.model.CognitoUser;
import io.github.hectorvent.floci.services.cognito.model.UserPool;
import io.github.hectorvent.floci.services.cognito.model.UserPoolClient;
import io.github.hectorvent.floci.services.cognito.verification.CognitoMessageDispatcher;
import io.github.hectorvent.floci.services.cognito.verification.VerificationCodeService;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.ses.SesService;
import io.github.hectorvent.floci.services.sns.SnsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@code ResendConfirmationCode}: rate-limit, status guard, code
 * invalidation. Uses a {@link MutableClock} so we can simulate the 30s window.
 */
class CognitoResendFlowTest {

    private static final Pattern CODE_REGEX = Pattern.compile("\\b(\\d{6})\\b");

    private CognitoService service;
    private SesService ses;
    private SnsService sns;
    private MutableClock clock;
    private UserPool pool;
    private UserPoolClient client;

    @BeforeEach
    void setUp() {
        ses = mock(SesService.class);
        sns = mock(SnsService.class);
        clock = new MutableClock(Instant.parse("2026-05-15T12:00:00Z"));

        StorageFactory storageFactory = mock(StorageFactory.class);
        when(storageFactory.create(anyString(), anyString(), any()))
                .thenAnswer(inv -> new InMemoryStorage<>());

        VerificationCodeService verificationCodes =
                new VerificationCodeService(storageFactory, clock);
        CognitoMessageDispatcher dispatcher = new CognitoMessageDispatcher(ses, sns);

        service = new CognitoService(
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                new InMemoryStorage<>(), new InMemoryStorage<>(),
                "http://localhost:4566",
                new RegionResolver("us-east-1", "000000000000"),
                mock(LambdaService.class),
                verificationCodes, dispatcher);

        pool = service.createUserPool(Map.of("PoolName", "ResendPool"), "us-east-1");
        client = service.createUserPoolClient(pool.getId(), "resend-client",
                false, false, List.of(), List.of());
    }

    @Test
    void resend_after30s_emitsNewCodeAndInvalidatesFirst() {
        service.signUp(client.getClientId(), "alice@example.com", "Pass1234!",
                Map.of("email", "alice@example.com"));
        String firstCode = readLatestCodeFor("alice@example.com");

        clock.advance(Duration.ofSeconds(31));
        service.resendConfirmationCode(client.getClientId(), "alice@example.com");
        String secondCode = readLatestCodeFor("alice@example.com");

        assertNotEquals(firstCode, secondCode, "resend issues a different code");

        // First code no longer valid (overwritten)
        AwsException ex = assertThrows(AwsException.class,
                () -> service.confirmSignUp(client.getClientId(), "alice@example.com", firstCode));
        assertEquals("CodeMismatchException", ex.getErrorCode());

        // Second code confirms successfully
        assertDoesNotThrow(() ->
                service.confirmSignUp(client.getClientId(), "alice@example.com", secondCode));
    }

    @Test
    void resend_withinRateLimitWindow_throwsLimitExceeded() {
        service.signUp(client.getClientId(), "bob@example.com", "Pass1234!",
                Map.of("email", "bob@example.com"));

        // Immediate resend — still within 30s window
        AwsException ex = assertThrows(AwsException.class,
                () -> service.resendConfirmationCode(client.getClientId(), "bob@example.com"));
        assertEquals("LimitExceededException", ex.getErrorCode());
    }

    @Test
    void resend_onConfirmedUser_throwsInvalidParameter() {
        service.signUp(client.getClientId(), "carol@example.com", "Pass1234!",
                Map.of("email", "carol@example.com"));
        String code = readLatestCodeFor("carol@example.com");
        service.confirmSignUp(client.getClientId(), "carol@example.com", code);

        AwsException ex = assertThrows(AwsException.class,
                () -> service.resendConfirmationCode(client.getClientId(), "carol@example.com"));
        assertEquals("InvalidParameterException", ex.getErrorCode());
    }

    @Test
    void resend_returnsCodeDeliveryDetails() {
        service.signUp(client.getClientId(), "dave@example.com", "Pass1234!",
                Map.of("email", "dave@example.com"));
        clock.advance(Duration.ofSeconds(31));

        Map<String, Object> result =
                service.resendConfirmationCode(client.getClientId(), "dave@example.com");
        @SuppressWarnings("unchecked")
        Map<String, Object> cdd = (Map<String, Object>) result.get("CodeDeliveryDetails");
        assertEquals("EMAIL", cdd.get("DeliveryMedium"));
        assertEquals("email", cdd.get("AttributeName"));
    }

    // ───────────────────────── helpers ─────────────────────────

    private String readLatestCodeFor(String email) {
        @SuppressWarnings("unchecked")
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> toCaptor = ArgumentCaptor.forClass(List.class);
        verify(ses, atLeastOnce()).sendEmail(
                anyString(), toCaptor.capture(), any(), any(), any(),
                anyString(), bodyCaptor.capture(), any(), anyString());

        List<List<String>> tos = toCaptor.getAllValues();
        List<String> bodies = bodyCaptor.getAllValues();
        for (int i = tos.size() - 1; i >= 0; i--) {
            if (tos.get(i).contains(email)) {
                Matcher m = CODE_REGEX.matcher(bodies.get(i));
                if (m.find()) return m.group(1);
            }
        }
        throw new AssertionError("No 6-digit code in dispatched emails to " + email);
    }

    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant start) { this.now = start; }
        void advance(Duration d) { now = now.plus(d); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
