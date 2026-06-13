package app.zylos.hello.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import app.zylos.hello.support.AbstractOidcStubbedTest;
import app.zylos.security.opa.CachingOpaClient;
import app.zylos.security.opa.OpaClient;

/**
 * Proves the in-service fine-grained path: hello calls centralized OPA for a
 * resource-level decision, the decision is cached (single-flight Caffeine), and
 * allow/deny map to 200/403.
 *
 * <p>A real OPA container loads the same policy published by zylos-infra-policies
 * (mirrored as a test fixture). Identity is injected via spring-security-test's
 * jwt() post-processor; every request carries the gateway act chain so the
 * actor-chain layer always passes and OPA is the deciding gate. Authorization
 * turns on realm_access.roles.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@Import(app.zylos.security.autoconfigure.ZylosOpaServletAutoConfiguration.class)
class OpaFineGrainedIT extends AbstractOidcStubbedTest {

    @Container
    @SuppressWarnings("resource")
    static final GenericContainer<?> OPA = new GenericContainer<>("openpolicyagent/opa:1.15.2-static")
            .withCopyFileToContainer(MountableFile.forClasspathResource("opa/common.rego"), "/policy/common.rego")
            .withCopyFileToContainer(MountableFile.forClasspathResource("opa/hello.rego"), "/policy/hello.rego")
            .withCommand("run", "--server", "--addr=0.0.0.0:8181", "/policy")
            .withExposedPorts(8181)
            .waitingFor(Wait.forHttp("/health").forPort(8181).forStatusCode(200));

    @DynamicPropertySource
    static void opaProperties(DynamicPropertyRegistry registry) {
        registry.add("zylos.security.opa.endpoint", () -> "http://" + OPA.getHost() + ":" + OPA.getMappedPort(8181));
    }

    @Autowired
    MockMvc mockMvc;

    @Autowired
    OpaClient opaClient;

    private static JwtRequestPostProcessor delegated(List<String> roles) {
        return jwt().jwt(builder -> builder.subject("user-123")
                .audience(List.of("zylos-internal-hello"))
                .claim("azp", "zylos-gateway")
                .claim("act", Map.of("client_id", "zylos-gateway"))
                .claim("realm_access", Map.of("roles", roles)));
    }

    @Test
    void customerRoleIsAllowedByOpa() throws Exception {
        mockMvc.perform(get("/api/v1/hello/me").with(delegated(List.of("customer"))))
                .andExpect(status().isOk());
    }

    @Test
    void missingRoleIsDeniedByOpa() throws Exception {
        mockMvc.perform(get("/api/v1/hello/me").with(delegated(List.of()))).andExpect(status().isForbidden());
    }

    @Test
    void decisionsAreCached() throws Exception {
        CachingOpaClient caching = (CachingOpaClient) opaClient;
        caching.invalidateAll();

        mockMvc.perform(get("/api/v1/hello/me").with(delegated(List.of("admin"))))
                .andExpect(status().isOk());
        long afterFirst = caching.size();
        mockMvc.perform(get("/api/v1/hello/me").with(delegated(List.of("admin"))))
                .andExpect(status().isOk());
        long afterSecond = caching.size();

        assertThat(afterFirst).isEqualTo(1); // first call populated the cache
        assertThat(afterSecond).isEqualTo(afterFirst); // identical second call hit the cache, no new entry
    }
}
