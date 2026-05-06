package app.zylos.hello.application;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import app.zylos.hello.domain.Greeting;

@Service
public class GreetingService {

    private final String version;
    private final String podName;

    public GreetingService(
            @Value("${app.version:0.0.0}") String version, @Value("${HOSTNAME:unknown}") String podName) {
        this.version = version;
        this.podName = podName;
    }

    public Greeting greet(String name) {
        return Greeting.create(name == null || name.isBlank() ? "world" : name, version, podName);
    }
}
