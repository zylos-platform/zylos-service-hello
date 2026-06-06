package app.zylos.hello.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;

/**
 * The full-slice end-to-end proof: a real custom Keycloak (with the
 * ActClaimMapper baked in) issues and exchanges tokens; the running hello
 * service validates them through the real starter components.
 *
 * <p>Exercises every layer together for the first time:
 * <ul>
 *   <li>real RFC 8693 exchange (gateway → hello) producing a real {@code act}
 *       claim via the ActClaimMapper;</li>
 *   <li>the starter's {@code JwtDecoder} validating signature/iss/aud against
 *       real Keycloak;</li>
 *   <li>the starter's {@code ActorChainAuthorizationManager} matching the real
 *       {@code act} chain against the chain-sensitive greeting policy.</li>
 * </ul>
 *
 * <p>Uses the published custom image (anonymous-pullable from GHCR) in
 * {@code start-dev} mode: the final image carries no {@code KC_DB}, so dev mode
 * re-augments with H2 while keeping the baked mapper — no Postgres needed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class FullSliceSecurityIT {

    @Container
    static final KeycloakContainer KEYCLOAK = new KeycloakContainer(
                    "ghcr.io/zylos-platform/keycloak:26.6.1-zylos-act-0.1.0")
            .withRealmImportFile("/zylos-fullslice-realm.json");

    private static final String REALM = "zylos-fullslice";
    private static final String GATEWAY = "zylos-gateway";
    private static final String GATEWAY_SECRET = "dev-secret-gateway";
    private static final String HELLO = "zylos-internal-hello";
    private static final String HELLO_SECRET = "dev-secret-hello";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("zylos.security.issuer-uri", () -> KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM);
        registry.add(
                "zylos.security.jwk-set-uri",
                () -> KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM + "/protocol/openid-connect/certs");
        registry.add("zylos.security.expected-audience", () -> HELLO);
        registry.add("zylos.security.actor-chains.enabled", () -> "true");
    }

    // --- helpers -----------------------------------------------------------

    private static URI tokenEndpoint() {
        return URI.create(KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM + "/protocol/openid-connect/token");
    }

    private static String clientCredentials(String clientId, String secret) throws Exception {
        String form = "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + secret;
        return postToken(form);
    }

    @SuppressWarnings("SameParameterValue")
    private static String exchange(String client, String secret, String subjectToken, String audience)
            throws Exception {
        String tokenType = "urn:ietf:params:oauth:token-type:access_token";
        String grantType = "urn:ietf:params:oauth:grant-type:token-exchange";

        String form = "grant_type=" + grantType
                + "&client_id=" + client
                + "&client_secret=" + secret
                + "&subject_token=" + subjectToken
                + "&subject_token_type=" + tokenType
                + "&audience=" + audience
                + "&scope=hello-aud";
        return postToken(form);
    }

    private static String postToken(String form) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(tokenEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Token request failed (" + response.statusCode() + "): " + response.body());
        }
        return MAPPER.readTree(response.body()).get("access_token").asText();
    }

    @SuppressWarnings("SameParameterValue")
    private static JsonNode claim(String jwt, String name) throws Exception {
        String payload = jwt.split("\\.")[1];
        byte[] decoded = java.util.Base64.getUrlDecoder().decode(payload);
        return MAPPER.readTree(decoded).get(name);
    }

    @Test
    void gatewayDelegatedRequestIsPermitted() throws Exception {
        String gatewayToken = clientCredentials(GATEWAY, GATEWAY_SECRET);
        String exchanged = exchange(GATEWAY, GATEWAY_SECRET, gatewayToken, HELLO);

        // Sanity: the exchanged token really carries act.client_id = zylos-gateway.
        assertThat(claim(exchanged, "act").get("client_id").asText()).isEqualTo(GATEWAY);

        HttpResponse<String> response = callGreeting(exchanged);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("Hello from Zylos");
    }

    @Test
    void directRequestWithoutActChainIsForbidden() throws Exception {
        // A direct client_credentials token for hello: aud=zylos-internal-hello
        // (audience mapper) but no act (no exchange). Passes the decoder, fails
        // the chain-sensitive policy → 403.
        String direct = clientCredentials(HELLO, HELLO_SECRET);

        HttpResponse<String> response = callGreeting(direct);

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    void wrongAudienceTokenIsUnauthorized() throws Exception {
        // A gateway token (aud != zylos-internal-hello) is rejected by the
        // decoder before authorization runs → 401.
        String gatewayToken = clientCredentials(GATEWAY, GATEWAY_SECRET);

        System.out.println("Gateway token (for debugging): " + gatewayToken);

        HttpResponse<String> response = callGreeting(gatewayToken);

        assertThat(response.statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> callGreeting(String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/hello/me"))
                .header("Authorization", "Bearer " + token)
                .GET()
                .build();
        return HTTP.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
