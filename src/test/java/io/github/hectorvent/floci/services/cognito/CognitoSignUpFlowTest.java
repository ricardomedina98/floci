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
import io.github.hectorvent.floci.services.lambda.model.InvocationType;
import io.github.hectorvent.floci.services.lambda.model.InvokeResult;
import io.github.hectorvent.floci.services.ses.SesService;
import io.github.hectorvent.floci.services.sns.SnsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * End-to-end tests of the SignUp → ConfirmSignUp flow with real code
 * issuance/validation. The dispatcher is wired to mock SES/SNS so we can
 * intercept the rendered code in test.
 */
class CognitoSignUpFlowTest {

    private static final Pattern CODE_REGEX = Pattern.compile("\\b(\\d{6})\\b");

    private CognitoService service;
    private SesService ses;
    private SnsService sns;
    private LambdaService lambdaService;
    private UserPool pool;
    private UserPoolClient client;

    @BeforeEach
    void setUp() {
        ses = mock(SesService.class);
        sns = mock(SnsService.class);
        lambdaService = mock(LambdaService.class);

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
                lambdaService,
                verificationCodes, dispatcher);

        pool = service.createUserPool(Map.of("PoolName", "FlowPool"), "us-east-1");
        client = service.createUserPoolClient(pool.getId(), "flow-client",
                false,           // generateSecret
                false,           // allowedOAuthFlowsUserPoolClient
                List.of(), List.of());
    }

    @Test
    void signUp_thenConfirmSignUp_withCorrectCode_marksUserConfirmed() {
        service.signUp(client.getClientId(), "alice@example.com", "Pass1234!",
                Map.of("email", "alice@example.com"));

        String code = readCodeFromLastEmail("alice@example.com");
        service.confirmSignUp(client.getClientId(), "alice@example.com", code);

        CognitoUser user = service.adminGetUser(pool.getId(), "alice@example.com");
        assertEquals("CONFIRMED", user.getUserStatus());
        assertEquals("true", user.getAttributes().get("email_verified"));
    }

    @Test
    void confirmSignUp_wrongCode_throwsCodeMismatch() {
        service.signUp(client.getClientId(), "bob@example.com", "Pass1234!",
                Map.of("email", "bob@example.com"));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.confirmSignUp(client.getClientId(), "bob@example.com", "000000"));
        assertEquals("CodeMismatchException", ex.getErrorCode());

        // User stays UNCONFIRMED
        CognitoUser user = service.adminGetUser(pool.getId(), "bob@example.com");
        assertEquals("UNCONFIRMED", user.getUserStatus());
    }

    @Test
    void signUp_withAutoConfirmTrigger_doesNotIssueCodeOrSendEmail() {
        // Configure pool with PreSignUp trigger that returns autoConfirmUser=true
        Map<String, Object> updateReq = new HashMap<>();
        updateReq.put("UserPoolId", pool.getId());
        updateReq.put("LambdaConfig", Map.of("PreSignUp", "arn:aws:lambda:::pre-signup-auto"));
        service.updateUserPool(updateReq, "us-east-1");

        when(lambdaService.invoke(anyString(), eq("arn:aws:lambda:::pre-signup-auto"),
                any(byte[].class), eq(InvocationType.RequestResponse)))
                .thenReturn(lambdaOk("""
                        {"response":{"autoConfirmUser":true,"autoVerifyEmail":true}}"""));

        service.signUp(client.getClientId(), "carol@example.com", "Pass1234!",
                Map.of("email", "carol@example.com"));

        CognitoUser user = service.adminGetUser(pool.getId(), "carol@example.com");
        assertEquals("CONFIRMED", user.getUserStatus());

        // No email/SMS dispatched when autoConfirm
        verify(ses, never()).sendEmail(anyString(), any(), any(), any(), any(),
                anyString(), anyString(), any(), anyString());
        verify(sns, never()).publish(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void confirmSignUp_alreadyConfirmedUser_throws() {
        service.signUp(client.getClientId(), "dave@example.com", "Pass1234!",
                Map.of("email", "dave@example.com"));
        String code = readCodeFromLastEmail("dave@example.com");
        service.confirmSignUp(client.getClientId(), "dave@example.com", code);

        AwsException ex = assertThrows(AwsException.class,
                () -> service.confirmSignUp(client.getClientId(), "dave@example.com", code));
        assertEquals("NotAuthorizedException", ex.getErrorCode());
    }

    // ───────────────────────── helpers ─────────────────────────

    /**
     * Extract the 6-digit verification code from the most recent email the
     * dispatcher sent to {@code email}. Reads via Mockito capture so we don't
     * need a real SesService for these unit tests.
     */
    private String readCodeFromLastEmail(String email) {
        @SuppressWarnings("unchecked")
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> toCaptor = ArgumentCaptor.forClass(List.class);
        verify(ses, org.mockito.Mockito.atLeastOnce()).sendEmail(
                anyString(), toCaptor.capture(), any(), any(), any(),
                anyString(), bodyCaptor.capture(), any(), anyString());

        // Walk captures in reverse to find the most recent for this email
        List<List<String>> tos = toCaptor.getAllValues();
        List<String> bodies = bodyCaptor.getAllValues();
        for (int i = tos.size() - 1; i >= 0; i--) {
            if (tos.get(i).contains(email)) {
                Matcher m = CODE_REGEX.matcher(bodies.get(i));
                if (m.find()) return m.group(1);
            }
        }
        throw new AssertionError("No 6-digit code found in dispatched emails to " + email);
    }

    private InvokeResult lambdaOk(String body) {
        return new InvokeResult(
                200, null, body.getBytes(StandardCharsets.UTF_8), null, "req-id");
    }
}
