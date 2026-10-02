package io.github.eunini.issuer.web;

import io.github.eunini.issuer.auth.AuthorizationService;
import io.github.eunini.issuer.cards.CardModels.*;
import io.github.eunini.issuer.cards.CardService;
import io.github.eunini.issuer.clearing.ClearingService;
import io.github.eunini.issuer.clearing.ClearingService.IngestReport;
import io.github.eunini.issuer.disputes.DisputeModels.*;
import io.github.eunini.issuer.disputes.DisputeService;
import io.github.eunini.issuer.ledger.LedgerService;
import io.github.eunini.issuer.ledger.LedgerService.TrialBalance;
import jakarta.validation.Valid;
import java.time.Clock;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

/** Back-office operations API (card management, clearing, disputes, ledger). */
@RestController
@RequestMapping("/api/v1")
public class AdminController {

    private final CardService cards;
    private final AuthorizationService auths;
    private final ClearingService clearing;
    private final DisputeService disputes;
    private final LedgerService ledger;
    private final Clock clock;

    public AdminController(CardService cards, AuthorizationService auths, ClearingService clearing,
                           DisputeService disputes, LedgerService ledger, Clock clock) {
        this.cards = cards;
        this.auths = auths;
        this.clearing = clearing;
        this.disputes = disputes;
        this.ledger = ledger;
        this.clock = clock;
    }

    @PostMapping("/cards/import")
    public List<ImportResult> importCards(@RequestBody List<@Valid CardImport> body) {
        return cards.importCards(body);
    }

    @PostMapping("/cards/{id}/status")
    public Map<String, String> status(@PathVariable long id, @Valid @RequestBody StatusChange s) {
        cards.changeStatus(id, s, "ops");
        return Map.of("status", s.status());
    }

    @GetMapping("/accounts/{id}")
    public AccountView account(@PathVariable long id) {
        return cards.account(id);
    }

    @PostMapping("/accounts/{id}/deposits")
    public Map<String, Long> deposit(@PathVariable long id, @Valid @RequestBody Deposit d) {
        return Map.of("entryId", cards.deposit(id, d));
    }

    @GetMapping("/advices")
    public List<AuthorizationService.AdviceView> advices(@RequestParam String authRef) {
        return auths.advicesFor(authRef);
    }

    @PostMapping("/holds/expire")
    public Map<String, Integer> expire(@RequestParam(required = false) String asOf) {
        OffsetDateTime t = asOf == null ? OffsetDateTime.now(clock) : OffsetDateTime.parse(asOf);
        return Map.of("expired", auths.expireHolds(t));
    }

    @PostMapping(value = "/clearing/files", consumes = MediaType.TEXT_PLAIN_VALUE)
    public IngestReport ingest(@RequestBody String file) {
        return clearing.ingest(file);
    }

    @GetMapping(value = "/clearing/outgoing", produces = MediaType.TEXT_PLAIN_VALUE)
    public String outgoing(@RequestParam(defaultValue = "OUT-1") String fileId) {
        return disputes.outgoingFile(fileId, LocalDate.now(clock));
    }

    @PostMapping("/disputes")
    public DisputeView open(@Valid @RequestBody OpenDispute req) {
        return disputes.open(req);
    }

    @GetMapping("/disputes/{id}")
    public DisputeView dispute(@PathVariable long id) {
        return disputes.view(id);
    }

    @PostMapping("/disputes/{id}/evidence")
    public DisputeView evidence(@PathVariable long id, @Valid @RequestBody Evidence e) {
        return disputes.addEvidence(id, e);
    }

    @PostMapping("/disputes/{id}/chargeback")
    public DisputeView chargeback(@PathVariable long id) {
        return disputes.raiseChargeback(id, "ops");
    }

    @PostMapping("/disputes/{id}/resolve")
    public DisputeView resolve(@PathVariable long id, @Valid @RequestBody Resolution r) {
        return disputes.resolve(id, r);
    }

    @PostMapping("/disputes/deadlines/run")
    public List<Transition> deadlines(@RequestParam(required = false) String asOf) {
        return disputes.runDeadlines(asOf == null ? LocalDate.now(clock) : LocalDate.parse(asOf));
    }

    @GetMapping("/ledger/trial-balance")
    public TrialBalance trialBalance() {
        return ledger.trialBalance();
    }
}
