# ADR 0001: Security Integration

- **Status:** Accepted
- **Date:** 2026-05-31
- **Relates to:** starter ADR 0001–0006; parent ADR 0004; gitops ADR 0011/0013

## Context

`zylos-service-hello` is the reference internal service and the platform's
end-to-end validation vehicle. It previously shipped with no security, which
also violated the parent's mandatory-starter enforcer (ADR 0004). It must
become a Bearer-token resource server for the `zylos-internal-hello` audience
and validate the delegation chain on its endpoints.

## Decision

**Adopt `zylos-infra-security-starter`.** Its servlet autoconfiguration
supplies the `JwtDecoder` (JWKS signature, `iss`, `aud == zylos-internal-hello`,
skew, unknown-kid refresh), the `ActorChainAuthorizationManager`, MDC
enrichment, and identity metrics. This both adds security and satisfies the
enforcer.

**Stateless servlet `SecurityFilterChain`.** `/api/v1/**` is authorized by the
actor-chain manager; everything else requires authentication. JWT resource
server with the starter's decoder. CSRF disabled, sessions stateless — pure
Bearer.

**Greeting is chain-sensitive.** As the validation service, it marks
`/api/v1/greeting` `chainSensitive: true` with `permittedChains: [[zylos-gateway]]`,
proving the full delegation path: reachable only via the gateway, denied on a
direct call. A typical non-sensitive endpoint would omit this.

**Local profile disables chain enforcement.** Local dev calls the service
directly (no gateway, no `act`), so `application-local.yaml` sets
`actor-chains.enabled: false`. Prod and tests keep it on.

## Rationale

- **Servlet, not reactive.** The service is a WebMVC app; the starter's servlet
  components apply. (The gateway exercises the reactive side.) This gives the
  starter real coverage on both stacks.

- **Chain-sensitive greeting demonstrates the spine.** The whole point of this
  service is to prove that a request carrying a gateway-issued `act` claim is
  accepted while an un-delegated request is rejected.

## Trade-offs Accepted

- **Greeting is artificially sensitive.** A real "hello" endpoint wouldn't be
  chain-sensitive. Acceptable: this is the reference/validation service, and the
  setting documents how to enforce delegation.

- **No outbound credentials.** The service only validates inbound tokens; it
  doesn't call other services, so it needs no client secret yet. Outbound
  service-to-service exchange (and the service's own client secret) is a later
  concern.

## Verification

- **Unit/slice** (`GreetingControllerTest`, OIDC-stubbed): unauthenticated →
  401; authenticated without `act` → 403; gateway-delegated (`act = zylos-gateway`)
  → 200.
- **Full slice** (`FullSliceSecurityIT`, real custom Keycloak via Testcontainers):
  a real RFC 8693 exchange (gateway → hello) yields a token whose `act.client_id`
  is genuinely `zylos-gateway`; the running service permits it (200), denies a
  direct un-delegated token (403), and rejects a wrong-audience token (401). This
  is the end-to-end proof that the ActClaimMapper's real `act` output and the
  starter's extractor/matcher agree against real Keycloak.

- **Claim model:** the full-slice realm mirrors production — `act` from a
  shared `zylos-actor` default scope on the calling client, `aud` from a
  `hello-aud` optional scope requested via `&scope` on exchange. The target
  client carries a self-audience mapper in the test realm only (to exercise the
  direct-token 403 path); production omits it.

## References

- starter ADR 0002 (JWT), 0003 (actor chains)
- parent ADR 0004 (mandatory starter); gitops ADR 0013 (act mapper image)
