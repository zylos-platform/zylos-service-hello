package app.zylos.hello.domain;

import java.time.Instant;

import org.jspecify.annotations.NullMarked;

@NullMarked
public record Greeting(String message, String version, Instant timestamp, String podName) {

    public static Greeting create(String name, String version, String podName) {
        return new Greeting("Hello from Zylos, " + name + "!", version, Instant.now(), podName);
    }
}
