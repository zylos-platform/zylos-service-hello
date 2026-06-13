package app.zylos.hello.adapters.inbound.rest;

import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import app.zylos.security.opa.OpaClient;

/**
 * Fine-grained authorization gate — the in-service, resource-level layer of the
 * defense-in-depth model, backed by centralized OPA. Active only when an
 * {@link OpaClient} is configured ({@code zylos.security.opa.endpoint} set);
 * otherwise a no-op, leaving the JWT + actor-chain layers to stand alone.
 *
 * <p>For hello (no domain resource) the gate lives in the inbound adapter where
 * identity is available. In a real domain service (e.g. Catalog) the same call
 * moves into the use-case after the aggregate loads, so the decision can include
 * resource ownership (e.g. {@code product.sellerId}). Same input contract; only
 * the call site differs.
 */
@Component
public class GreetingAuthorizer {

    static final String POLICY_PATH = "zylos/authz/hello/decision";

    private final ObjectProvider<OpaClient> opaClientProvider;

    public GreetingAuthorizer(ObjectProvider<OpaClient> opaClientProvider) {
        this.opaClientProvider = opaClientProvider;
    }

    @SuppressWarnings("unchecked")
    private static List<String> realmRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess == null) {
            return List.of();
        }
        Object roles = realmAccess.get("roles");
        return roles instanceof List<?> list ? List.copyOf((List<String>) list) : List.of();
    }

    public void authorize(Jwt jwt, String action, String resourceId) {
        OpaClient opa = opaClientProvider.getIfAvailable();
        if (opa == null) {
            return; // OPA not configured; fine-grained layer inactive.
        }
        OpaInput input = new OpaInput(
                new OpaInput.Subject(jwt.getSubject(), jwt.getClaimAsString("azp"), realmRoles(jwt)),
                action,
                new OpaInput.Resource("greeting", resourceId));
        if (!opa.check(POLICY_PATH, input)) {
            throw new AccessDeniedException("OPA denied " + action);
        }
    }

    /**
     * OPA input; records give the stable equals/hashCode the decision cache key relies on.
     */
    record OpaInput(Subject subject, String action, Resource resource) {
        record Subject(@Nullable String sub, @Nullable String clientId, List<String> roles) {}

        record Resource(String type, @Nullable String id) {}
    }
}
