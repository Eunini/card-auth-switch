package io.github.eunini.issuer;

import java.time.Clock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class IssuerApplication {

    public static void main(String[] args) {
        SpringApplication.run(IssuerApplication.class, args);
    }

    /** Injected everywhere time matters so tests can control deadlines and expiry. */
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
