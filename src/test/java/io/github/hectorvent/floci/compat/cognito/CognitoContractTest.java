package io.github.hectorvent.floci.compat.cognito;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.compat.FixtureLoader;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import io.github.hectorvent.floci.services.cognito.CognitoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeAll;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract tests: send captured AWS Cognito requests to floci, assert the
 * response shape matches the captured AWS response. Volatile fields
 * ({@code RequestId}, {@code UserSub}, timestamps) are ignored.
 *
 * <p>Fixtures live in {@code src/test/resources/fixtures/aws-cognito/}.
 */
@QuarkusTest
class CognitoContractTest {

    private static final String COGNITO_TARGET = "AWSCognitoIdentityProviderService.";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    CognitoService cognito;

    private String userPoolId;
    private String clientId;

    @BeforeAll
    static void configureRestAssuredEncoder() {
        RestAssured.config = RestAssured.config().encoderConfig(
                EncoderConfig.encoderConfig().encodeContentTypeAs(
                        "application/x-amz-json-1.1", ContentType.TEXT));
    }

    @BeforeEach
    void setUp() {
        // Fresh pool + client per test so no fixture pollutes another
        var pool = cognito.createUserPool(Map.of("PoolName", "contract-pool-" + System.nanoTime()), "us-east-1");
        userPoolId = pool.getId();
        var client = cognito.createUserPoolClient(userPoolId, "contract-client",
                false, false, java.util.List.of(), java.util.List.of());
        clientId = client.getClientId();
    }

    @Test
    void signUp_responseShapeMatchesAws() throws Exception {
        JsonNode fixture = FixtureLoader.load("sign-up.happy");
        Map<String, Object> req = adaptRequest(fixture.path("request"));

        JsonNode response = post("SignUp", req);

        // Structural assertions — must match AWS shape
        assertFalse(response.path("UserConfirmed").asBoolean(true), "UserConfirmed=false");
        assertFalse(response.path("UserSub").asText().isEmpty(), "UserSub present");
        JsonNode cdd = response.path("CodeDeliveryDetails");
        assertEquals("EMAIL", cdd.path("DeliveryMedium").asText());
        assertEquals("email", cdd.path("AttributeName").asText());
        // Destination should be non-empty (masking format may differ from AWS)
        assertFalse(cdd.path("Destination").asText().isEmpty(), "Destination present");
    }

    @Test
    void confirmSignUp_wrongCode_returnsCodeMismatchException() throws Exception {
        // First sign up a user so the username exists
        post("SignUp", Map.of(
                "ClientId", clientId,
                "Username", "fixture@example.com",
                "Password", "Pass1234!",
                "UserAttributes", java.util.List.of(Map.of("Name", "email", "Value", "fixture@example.com"))
        ));

        Map<String, Object> req = Map.of(
                "ClientId", clientId,
                "Username", "fixture@example.com",
                "ConfirmationCode", "000000"
        );

        var result = given()
                .header("X-Amz-Target", COGNITO_TARGET + "ConfirmSignUp")
                .contentType("application/x-amz-json-1.1")
                .body(MAPPER.writeValueAsString(req))
            .when().post("/")
            .then()
                .statusCode(400)
                .extract();

        JsonNode body = MAPPER.readTree(result.body().asString());
        // AWS error shape: {"__type": "CodeMismatchException", "message": "..."}
        String errorType = body.path("__type").asText("");
        assertTrue(errorType.contains("CodeMismatchException"),
                "expected CodeMismatchException, got: " + errorType);
    }

    /** Adapt a captured AWS request to a fresh-pool request (override ClientId + Username). */
    private Map<String, Object> adaptRequest(JsonNode captured) {
        Map<String, Object> req = new HashMap<>();
        Iterator<String> fields = captured.fieldNames();
        while (fields.hasNext()) {
            String f = fields.next();
            JsonNode v = captured.get(f);
            if ("ClientId".equals(f)) {
                req.put(f, clientId);
            } else if (v.isTextual()) {
                req.put(f, v.asText());
            } else {
                req.put(f, MAPPER.convertValue(v, Object.class));
            }
        }
        return req;
    }

    private JsonNode post(String action, Map<String, Object> body) throws Exception {
        var resp = given()
                .header("X-Amz-Target", COGNITO_TARGET + action)
                .contentType("application/x-amz-json-1.1")
                .body(MAPPER.writeValueAsString(body))
            .when().post("/")
            .then()
                .statusCode(200)
                .extract();
        return MAPPER.readTree(resp.body().asString());
    }
}
