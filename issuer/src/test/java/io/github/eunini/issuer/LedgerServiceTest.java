package io.github.eunini.issuer;

import static io.github.eunini.issuer.ledger.LedgerService.Leg.credit;
import static io.github.eunini.issuer.ledger.LedgerService.Leg.debit;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

class LedgerServiceTest extends IntegrationTest {

    @Autowired TransactionTemplate tx;

    @Test
    void rejectsUnbalancedAndNonPositiveEntries() {
        long cash = ledger.internal("ISSUER_CASH", "840");
        long net = ledger.internal("NETWORK_SETTLEMENT", "840");
        assertThatThrownBy(() -> tx.executeWithoutResult(s ->
            ledger.post("TEST", ref(), "bad", List.of(debit(cash, 100), credit(net, 99)))))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("unbalanced");
        assertThatThrownBy(() -> tx.executeWithoutResult(s ->
            ledger.post("TEST", ref(), "bad", List.of(debit(cash, 0), credit(net, 0)))))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void postingIsIdempotentByReference() {
        var card = issue(0);
        long chl = jdbc.sql("SELECT ledger_account_id FROM card_accounts WHERE id = ?").param(card.accountId())
            .query(Long.class).single();
        long cash = ledger.internal("ISSUER_CASH", "840");
        String r = ref();
        var first = tx.execute(s -> ledger.post("DEPOSIT", r, "x", List.of(debit(cash, 500), credit(chl, 500))));
        var second = tx.execute(s -> ledger.post("DEPOSIT", r, "x", List.of(debit(cash, 500), credit(chl, 500))));
        assertThat(first.created()).isTrue();
        assertThat(second.created()).isFalse();
        assertThat(second.entryId()).isEqualTo(first.entryId());
        assertThat(ledger.balance(chl)).isEqualTo(500);
    }

    @Test
    void trialBalanceIsBalancedAndMatchesMaterialisedBalances() {
        issue(12_345);
        issue(1);
        var tb = ledger.trialBalance();
        assertThat(tb.balanced()).isTrue();
        assertThat(tb.materialisedBalancesMatch()).isTrue();
        assertThat(tb.totalDebitsMinor()).isEqualTo(tb.totalCreditsMinor());
    }
}
