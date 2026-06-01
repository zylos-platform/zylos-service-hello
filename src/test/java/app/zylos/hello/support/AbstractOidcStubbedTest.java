package app.zylos.hello.support;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.github.tomakehurst.wiremock.WireMockServer;

/**
 * Base for security-enabled Spring tests. Stands up a WireMock OIDC provider so
 * the starter's {@code JwtDecoder} resolves discovery/JWKS at context startup
 * without a real Keycloak. Tests authenticate via {@code spring-security-test}'s
 * {@code jwt()} post-processor, so no real tokens are minted here.
 */
public abstract class AbstractOidcStubbedTest {

    protected static final WireMockServer KEYCLOAK =
            new WireMockServer(options().dynamicPort());
    private static final String REALM_PATH = "/realms/zylos";

    private static String issuer() {
        return KEYCLOAK.baseUrl().replace("localhost", "127.0.0.1") + REALM_PATH;
    }

    @BeforeAll
    static void startOidc() {
        KEYCLOAK.start();
        KEYCLOAK.stubFor(get(urlEqualTo(REALM_PATH + "/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                        {
                          "issuer": "%1$s",
                          "jwks_uri": "%1$s/protocol/openid-connect/certs",
                          "token_endpoint": "%1$s/protocol/openid-connect/token",
                          "authorization_endpoint": "%1$s/protocol/openid-connect/auth",
                          "response_types_supported": ["code"],
                          "subject_types_supported": ["public"],
                          "id_token_signing_alg_values_supported": ["RS256"]
                        }
                        """.formatted(issuer()))));
        KEYCLOAK.stubFor(get(urlEqualTo(REALM_PATH + "/protocol/openid-connect/certs"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                    {
                      "keys": [
                        {
                          "kty": "RSA",
                          "alg": "RS256",
                          "use": "sig",
                          "kid": "wiremock-stub-key",
                          "e": "AQAB",
                          "n": "rU91X3E-2nZkX-P_n-n7F_fV5_z8Z_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8_8"
                        }
                      ]
                    }
                    """)));
    }

    @AfterAll
    static void stopOidc() {
        KEYCLOAK.stop();
    }

    @DynamicPropertySource
    static void securityProperties(DynamicPropertyRegistry registry) {
        registry.add("zylos.security.issuer-uri", AbstractOidcStubbedTest::issuer);
        registry.add("zylos.security.expected-audience", () -> "zylos-internal-hello");
        registry.add("zylos.security.actor-chains.enabled", () -> "true");
    }
}
