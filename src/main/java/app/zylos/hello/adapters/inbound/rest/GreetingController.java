package app.zylos.hello.adapters.inbound.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import app.zylos.hello.application.GreetingService;
import app.zylos.hello.domain.Greeting;

@RestController
@RequestMapping("/api/v1")
public class GreetingController {

    private final GreetingService service;

    public GreetingController(GreetingService service) {
        this.service = service;
    }

    @GetMapping("/greeting")
    public Greeting greeting(@RequestParam(required = false, defaultValue = "world") String name) {
        return service.greet(name);
    }
}
