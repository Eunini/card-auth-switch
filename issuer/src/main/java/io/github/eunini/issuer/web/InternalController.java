package io.github.eunini.issuer.web;

import io.github.eunini.issuer.auth.AuthModels.*;
import io.github.eunini.issuer.auth.AuthorizationService;
import io.github.eunini.issuer.cards.CardModels.CardProfile;
import io.github.eunini.issuer.cards.CardService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.*;

/** Fast internal API used by the switch. Not exposed outside the processing network. */
@RestController
@RequestMapping("/internal/v1")
public class InternalController {

    private final AuthorizationService auths;
    private final CardService cards;

    public InternalController(AuthorizationService auths, CardService cards) {
        this.auths = auths;
        this.cards = cards;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }

    @GetMapping("/cards/snapshot")
    public List<CardProfile> snapshot() {
        return cards.snapshot();
    }

    @PostMapping("/authorizations")
    public AuthResponse authorize(@Valid @RequestBody AuthRequest r) {
        return auths.authorize(r);
    }

    @PostMapping("/advices")
    public StatusResponse advice(@Valid @RequestBody AdviceRequest a) {
        return auths.advice(a);
    }

    @PostMapping("/reversals")
    public StatusResponse reverse(@Valid @RequestBody ReversalRequest r) {
        return auths.reverse(r);
    }
}
