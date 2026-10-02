package io.github.eunini.issuer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.eunini.issuer.clearing.ClearingService;
import io.github.eunini.issuer.common.ApiException;
import io.github.eunini.issuer.disputes.DisputeModels.*;
import io.github.eunini.issuer.disputes.DisputeService;
import java.time.Duration;
import java.time.LocalDate;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class DisputeServiceTest extends IntegrationTest {

    @Autowired ClearingService clearing;
    @Autowired DisputeService disputes;

    record Purchase(long accountId, String recordId, String arn) {}

    Purchase purchase(long amount) {
        String pan = newPan();
        var c = issue(pan, 50_000, 0, "ACTIVE");
        var a = auths.authorize(auth(c, ref(), amount));
        String recordId = "R-" + UUID.randomUUID();
        String arn = ClearingServiceTest.arn();
        String d = LocalDate.now(clock).toString().replace("-", "");
        clearing.ingest("HDR|CASCLR|1|F-" + UUID.randomUUID() + "|" + d + "|ACQ1\n"
            + "PRES|" + recordId + "|" + arn + "|" + pan + "|" + a.authCode() + "|627512000001|TERM0001|" + d + "|"
            + amount + "|840|5732|Electronics Store|1|1\n" + "TRL|1|" + amount + "\n");
        return new Purchase(c.accountId(), recordId, arn);
    }

    void network(String type, String arn, long id, long amount, String extra) {
        String d = LocalDate.now(clock).toString().replace("-", "");
        var r = clearing.ingest("HDR|CASCLR|1|F-" + UUID.randomUUID() + "|" + d + "|NET\n"
            + type + "|N-" + UUID.randomUUID() + "|" + arn + "|" + DisputeService.ref(id) + "|" + amount + "|840|"
            + extra + "\n" + "TRL|1|" + amount + "\n");
        assertThat(r.lines().getFirst().outcome()).doesNotStartWith("UNMATCHED");
    }

    long balance(long accountId) {
        return cards.account(accountId).ledgerBalanceMinor();
    }

    @Test
    void fullLifecycleRepresentmentAccepted() {
        var p = purchase(20_000);
        assertThat(balance(p.accountId())).isEqualTo(30_000);

        var d = disputes.open(new OpenDispute(p.recordId(), "13.1", 20_000, "laptop never arrived"));
        assertThat(d.state()).isEqualTo("OPENED");
        assertThat(d.chargebackDeadline()).isEqualTo(LocalDate.now(clock).plusDays(120));
        assertThat(balance(p.accountId())).as("provisional credit").isEqualTo(50_000);

        assertThatThrownBy(() -> disputes.raiseChargeback(d.id(), "ops"))
            .isInstanceOf(ApiException.class).hasMessageContaining("CARDHOLDER_LETTER");
        disputes.addEvidence(d.id(), new Evidence("CARDHOLDER_LETTER", "signed letter", "cardholder"));
        assertThat(disputes.raiseChargeback(d.id(), "ops").state()).isEqualTo("CHARGEBACK_SENT");

        network("CHBK", p.arn(), d.id(), 20_000, "13.1");
        var settled = disputes.view(d.id());
        assertThat(settled.state()).isEqualTo("CHARGEBACK_SETTLED");
        assertThat(settled.representmentDeadline()).isEqualTo(LocalDate.now(clock).plusDays(30));

        clock.advance(Duration.ofDays(10));
        network("REPR", p.arn(), d.id(), 20_000, "proof of delivery signed");
        assertThat(disputes.view(d.id()).state()).isEqualTo("REPRESENTED");

        var closed = disputes.resolve(d.id(), new Resolution(Action.ACCEPT_REPRESENTMENT,
            "carrier signature matches cardholder", "ops"));
        assertThat(closed.state()).isEqualTo("CLOSED_LOST");
        assertThat(balance(p.accountId())).as("cardholder re-billed").isEqualTo(30_000);
        assertThat(closed.events()).extracting(EventView::toState).containsExactly(
            "OPENED", "OPENED", "CHARGEBACK_SENT", "CHARGEBACK_SETTLED", "REPRESENTED", "CLOSED_LOST");
        var tb = ledger.trialBalance();
        assertThat(tb.balanced()).isTrue();
        assertThat(tb.materialisedBalancesMatch()).isTrue();
    }

    @Test
    void preArbitrationWon() {
        var p = purchase(5_000);
        var d = disputes.open(new OpenDispute(p.recordId(), "4837", 5_000, "not me"));
        disputes.addEvidence(d.id(), new Evidence("CARDHOLDER_FRAUD_DECLARATION", "affidavit", "cardholder"));
        disputes.raiseChargeback(d.id(), "ops");
        network("CHBK", p.arn(), d.id(), 5_000, "4837");
        network("REPR", p.arn(), d.id(), 5_000, "AVS match");
        disputes.resolve(d.id(), new Resolution(Action.ESCALATE, "AVS is not proof of authorization", "ops"));
        var won = disputes.resolve(d.id(), new Resolution(Action.PREARB_WON, "acquirer accepted", "network"));
        assertThat(won.state()).isEqualTo("CLOSED_WON");
        assertThat(balance(p.accountId())).as("cardholder keeps the credit").isEqualTo(50_000);
    }

    @Test
    void deadlinesCloseDisputes() {
        var won = purchase(1_000);
        var d1 = disputes.open(new OpenDispute(won.recordId(), "12.6.1", 1_000, "charged twice"));
        disputes.addEvidence(d1.id(), new Evidence("TRANSACTION_RECORDS", "statement", "cardholder"));
        disputes.raiseChargeback(d1.id(), "ops");
        network("CHBK", won.arn(), d1.id(), 1_000, "12.6.1");

        var missed = purchase(700);
        var d2 = disputes.open(new OpenDispute(missed.recordId(), "13.3", 700, "broken"));

        clock.advance(Duration.ofDays(200));
        var transitions = disputes.runDeadlines(LocalDate.now(clock));
        assertThat(transitions).extracting(Transition::disputeId).contains(d1.id(), d2.id());
        assertThat(disputes.view(d1.id()).state()).isEqualTo("CLOSED_WON");
        assertThat(disputes.view(d2.id()).state()).isEqualTo("CLOSED_EXPIRED");
        // The issuer absorbs the provisional credit it can no longer recover.
        assertThat(balance(missed.accountId())).isEqualTo(50_000);
    }

    @Test
    void rulesAreEnforced() {
        var p = purchase(3_000);
        assertThatThrownBy(() -> disputes.open(new OpenDispute(p.recordId(), "13.1", 3_001, "x")))
            .hasMessageContaining("exceeds");
        assertThatThrownBy(() -> disputes.open(new OpenDispute(p.recordId(), "99.9", 3_000, "x")))
            .hasMessageContaining("unknown reason code");
        var d = disputes.open(new OpenDispute(p.recordId(), "13.1", 3_000, "x"));
        assertThatThrownBy(() -> disputes.open(new OpenDispute(p.recordId(), "13.1", 3_000, "x")))
            .hasMessageContaining("already exists");
        assertThatThrownBy(() -> disputes.resolve(d.id(), new Resolution(Action.PREARB_WON, "x", "ops")))
            .hasMessageContaining("pre-arbitration");
        assertThatThrownBy(() -> disputes.resolve(d.id(), new Resolution(Action.ESCALATE, "x", "ops")))
            .hasMessageContaining("cannot move");
        var w = disputes.resolve(d.id(), new Resolution(Action.WITHDRAW, "found it", "cardholder"));
        assertThat(w.state()).isEqualTo("CLOSED_WITHDRAWN");
        assertThat(balance(p.accountId())).isEqualTo(47_000);

        var late = purchase(100);
        clock.advance(Duration.ofDays(121));
        assertThatThrownBy(() -> disputes.open(new OpenDispute(late.recordId(), "13.1", 100, "x")))
            .hasMessageContaining("time limit");
    }
}
