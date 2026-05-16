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
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@code ForgotPassword} + {@code ConfirmForgotPassword}: full
 * round-trip + code validation + unknown-user LEGACY behavior (matches the
 * wirebit-stg pool's observed behavior).
 */
class CognitoForgotPasswordFlowTest {

    private static final Pattern CODE_REGEX = Pattern.compile("\\b(\\d{6})\\b");

    private CognitoService service;
    private SesService ses;
    private SnsService sns;
    private UserPool pool;
    private UserPoolClient client;

    @BeforeEach
    void setUp() {
        ses = mock(SesService.class);
        sns = mock(SnsService.class);

        StorageFactory storageFactory = mock(StorageFactory.class);
        when(storageFactory.create(anyString(), anyString(), any()))
                .thenAnswer(inv -> new InMemoryStorage<>());

        VerificationCodeService verificationCodes =
                new VerificationCodeService(storageFactory, Clock.systemUTC());
        CognitoMessageDispatcher dispatcher = new CognitoMessageDispatcher(ses, sns);

        service = new CognitoService(
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                new InMemoryStorage<>(), new InMemoryStorage<>(),
                "http://localhost:4566",
                new RegionResolver("us-east-1", "000000000000"),
                mock(LambdaService.class),
                verificationCodes, dispatcher);

        pool = service.createUserPool(Map.of("PoolName", "ForgotPool"), "us-east-1");
        client = service.createUserPoolClient(pool.getId(), "fp-client",
                false, false, List.of(), List.of());
    }

    @Test
    void fullFlow_confirmedUser_succeedsAndAllowsLoginWithNewPassword() {
        seedConfirmedUser("alice@example.com", "OldPass1!");

        Map<String, Object> fpResult = service.forgotPassword(client.getClientId(), "alice@example.com");
        assertNotNull(fpResult.get("CodeDeliveryDetails"));
        String code = readLatestCodeFor("alice@example.com");

        service.confirmForgotPassword(client.getClientId(), "alice@example.com", code, "NewPass1!");

        // Old password no longer authenticates
        AwsException oldEx = assertThrows(AwsException.class, () ->
                service.initiateAuth(client.getClientId(), "USER_PASSWORD_AUTH",
                        Map.of("USERNAME", "alice@example.com", "PASSWORD", "OldPass1!")));
        assertEquals("NotAuthorizedException", oldEx.getErrorCode());

        // New password works
        assertDoesNotThrow(() -> service.initiateAuth(client.getClientId(), "USER_PASSWORD_AUTH",
                Map.of("USERNAME", "alice@example.com", "PASSWORD", "NewPass1!")));
    }

    @Test
    void confirmForgotPassword_wrongCode_throwsCodeMismatch() {
        seedConfirmedUser("bob@example.com", "OldPass1!");
        service.forgotPassword(client.getClientId(), "bob@example.com");

        AwsException ex = assertThrows(AwsException.class, () ->
                service.confirmForgotPassword(client.getClientId(), "bob@example.com",
                        "000000", "NewPass1!"));
        assertEquals("CodeMismatchException", ex.getErrorCode());
    }

    @Test
    void confirmForgotPassword_codeFromADifferentUser_throwsCodeMismatch() {
        seedConfirmedUser("carol@example.com", "OldPass1!");
        seedConfirmedUser("dave@example.com",  "OldPass1!");

        service.forgotPassword(client.getClientId(), "carol@example.com");
        String carolCode = readLatestCodeFor("carol@example.com");

        AwsException ex = assertThrows(AwsException.class, () ->
                service.confirmForgotPassword(client.getClientId(), "dave@example.com",
                        carolCode, "NewPass1!"));
        assertEquals("CodeMismatchException", ex.getErrorCode());
    }

    @Test
    void forgotPassword_unknownUser_legacy_throwsUserNotFound() {
        // Wirebit stg pool returns UserNotFoundException (legacy mode).
        // PreventUserExistenceErrors=ENABLED is not yet modeled in floci's
        // UserPoolClient — when added (future PR), this test should be split.
        AwsException ex = assertThrows(AwsException.class, () ->
                service.forgotPassword(client.getClientId(), "ghost@example.com"));
        assertEquals("UserNotFoundException", ex.getErrorCode());
    }

    @Test
    void forgotPassword_unconfirmedUser_throwsInvalidParameter() {
        // AWS rejects ForgotPassword on UNCONFIRMED users with
        // InvalidParameterException ("Cannot reset password for the user as
        // there is no registered/verified email or phone_number")
        service.signUp(client.getClientId(), "unconfirmed@example.com", "Pass1234!",
                Map.of("email", "unconfirmed@example.com"));

        AwsException ex = assertThrows(AwsException.class, () ->
                service.forgotPassword(client.getClientId(), "unconfirmed@example.com"));
        assertEquals("InvalidParameterException", ex.getErrorCode());
    }

    // ───────────────────────── helpers ─────────────────────────

    private void seedConfirmedUser(String username, String password) {
        service.adminCreateUser(pool.getId(), username,
                Map.of("email", username, "email_verified", "true"), null);
        service.adminSetUserPassword(pool.getId(), username, password, true);
        CognitoUser u = service.adminGetUser(pool.getId(), username);
        u.setUserStatus("CONFIRMED");
    }

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
}
