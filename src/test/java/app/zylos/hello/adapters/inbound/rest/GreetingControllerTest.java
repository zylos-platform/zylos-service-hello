package app.zylos.hello.adapters.inbound.rest;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import app.zylos.hello.support.AbstractOidcStubbedTest;
import app.zylos.security.opa.OpaClient;

@SpringBootTest
@AutoConfigureMockMvc
class GreetingControllerTest extends AbstractOidcStubbedTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OpaClient opaClient;

    /**
     * A JWT whose actor chain is [zylos-gateway], as produced by gateway exchange.
     */
    private static JwtRequestPostProcessor gatewayDelegated() {
        return jwt().jwt(builder ->
                builder.audience(List.of("zylos-internal-hello")).claim("act", Map.of("client_id", "zylos-gateway")));
    }

    @Test
    void greetingRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/v1/hello/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void greetingDeniedWithoutGatewayActorChain() throws Exception {
        // Authenticated but no act claim → chain-sensitive endpoint denies (403).
        mockMvc.perform(get("/api/v1/hello/me").with(jwt())).andExpect(status().isForbidden());
    }

    @Test
    void greetingPermittedWhenDelegatedByGateway() throws Exception {
        Mockito.when(opaClient.check(Mockito.anyString(), Mockito.any())).thenReturn(true);

        mockMvc.perform(get("/api/v1/hello/me").with(gatewayDelegated()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", containsString("Hello from Zylos")))
                .andExpect(jsonPath("$.version").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void greetingAcceptsNameWhenDelegatedByGateway() throws Exception {
        Mockito.when(opaClient.check(Mockito.anyString(), Mockito.any())).thenReturn(true);

        mockMvc.perform(get("/api/v1/hello/me").param("name", "alice").with(gatewayDelegated()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", containsString("alice")));
    }
}
