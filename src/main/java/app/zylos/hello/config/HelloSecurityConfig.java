package app.zylos.hello.config;

import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import app.zylos.security.actor.ActorChainAuthorizationManager;

/**
 * Servlet security for the hello service.
 *
 * <p>A stateless Bearer-token resource server for the {@code zylos-internal-hello}
 * audience. The Zylos security starter supplies the {@code JwtDecoder} (signature
 * via JWKS, {@code iss} exact match, {@code aud == zylos-internal-hello}, clock
 * skew) — {@link Customizer#withDefaults()} on the JWT spec uses it.
 *
 * <p>Authorization on {@code /api/v1/**} is delegated to the starter's
 * {@link ActorChainAuthorizationManager}, which applies the policy in
 * {@code actor-chains.yaml}. Under the authorization model, endpoints are authenticated-
 * only unless marked {@code chainSensitive}; the greeting endpoint is marked
 * chain-sensitive here to demonstrate (and validate) delegation enforcement —
 * it is reachable only via the gateway (actor {@code zylos-gateway}).
 *
 * <p>Actuator runs on a separate management port (9000) with its own context,
 * so it is not covered by this 8080 chain.
 */
@Configuration
@EnableWebSecurity
public class HelloSecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain actuatorSecurityFilterChain(HttpSecurity http) {
        return http.securityMatcher(EndpointRequest.toAnyEndpoint())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http, ActorChainAuthorizationManager actorChainAuthorizationManager) {
        return http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/hello/**")
                        .access(actorChainAuthorizationManager)
                        .anyRequest()
                        .authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }
}
