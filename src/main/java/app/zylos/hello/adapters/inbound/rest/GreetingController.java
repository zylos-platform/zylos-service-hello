package app.zylos.hello.adapters.inbound.rest;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import app.zylos.hello.application.GreetingService;
import app.zylos.hello.domain.Greeting;

@RestController
@RequestMapping("/api/v1/hello")
public class GreetingController {

    private final GreetingService service;
    private final GreetingAuthorizer authorizer;

    public GreetingController(GreetingService service, GreetingAuthorizer authorizer) {
        this.service = service;
        this.authorizer = authorizer;
    }

    @GetMapping("/me")
    public Greeting greeting(
            @AuthenticationPrincipal Jwt jwt, @RequestParam(required = false, defaultValue = "world") String name) {
        authorizer.authorize(jwt, "greeting:read", name);
        return service.greet(name);
    }
}
