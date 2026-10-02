package io.github.eunini.issuer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.eunini.issuer.auth.AuthModels.AuthResponse;
import io.github.eunini.issuer.cards.CardModels.ImportResult;
import io.github.eunini.issuer.clearing.ClearingService;
import io.github.eunini.issuer.common.ApiException;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class ClearingServiceTest extends IntegrationTest {

    static final AtomicLong ARN_SEQ = new AtomicLong(java.util.concurrent.ThreadLocalRandom.current().nextLong(1_000_000_000L));

    @Autowired ClearingService clearing;

    static String arn() {
        return String.format("74100001626%012d", ARN_SEQ.incrementAndGet());
    }

    record Pres(String recordId, String arn, String pan, String authCode, String rrn, long amount, String mcc,
                int seq, int count) {
        String line(LocalDate d) {
            return "PRES|" + recordId + "|" + arn + "|" + pan + "|" + authCode + "|" + rrn + "|TERM0001|"
                + d.toString().replace("-", "") + "|" + amount + "|840|" + mcc + "|Test Merchant|" + seq + "|"
                + count;
        }
    }

    static Pres pres(String pan, String authCode, String rrn, long amount, String mcc, int seq, int count) {
        return new Pres("R-" + UUID.randomUUID(), arn(), pan, authCode, rrn, amount, mcc, seq, count);
    }

    String file(LocalDate d, List<String> lines, long total) {
        return "HDR|CASCLR|1|F-" + UUID.randomUUID() + "|" + d.toString().replace("-", "") + "|ACQ1\n"
            + String.join("\n", lines) + "\nTRL|" + lines.size() + "|" + total + "\n";
    }

    ClearingService.IngestReport ingest(Pres... ps) {
        LocalDate d = LocalDate.now(clock);
        long total = 0;
        List<String> lines = new java.util.ArrayList<>();
        for (Pres p : ps) {
            lines.add(p.line(d));
            total += p.amount();
        }
        return clearing.ingest(file(d, lines, total));
    }

    long ledgerBalance(ImportResult c) {
        return cards.account(c.accountId()).ledgerBalanceMinor();
    }

    @Test
    void exactMatchPostsAndReleasesHold() {
        String pan = newPan();
        var c = issue(pan, 10_000, 0, "ACTIVE");
        AuthResponse a = auths.authorize(auth(c, ref(), 4_250));
        var report = ingest(pres(pan, a.authCode(), "627512000001", 4_250, "5411", 1, 1));
        assertThat(report.lines().getFirst().outcome()).isEqualTo("MATCHED");
        var v = cards.account(c.accountId());
        assertThat(v.ledgerBalanceMinor()).isEqualTo(5_750);
        assertThat(v.heldMinor()).isZero();
        assertThat(v.availableMinor()).isEqualTo(5_750);
        assertThat(v.holds().getFirst().status()).isEqualTo("CLEARED");
    }

    @Test
    void multiplePresentmentsForOneAuthorization() {
        String pan = newPan();
        var c = issue(pan, 10_000, 0, "ACTIVE");
        AuthResponse a = auths.authorize(auth(c, ref(), 9_000));
        var r1 = ingest(pres(pan, a.authCode(), "627512000001", 3_000, "5999", 1, 2));
        assertThat(r1.lines().getFirst().outcome()).isEqualTo("MATCHED");
        var mid = cards.account(c.accountId());
        assertThat(mid.heldMinor()).isEqualTo(6_000);
        assertThat(mid.holds().getFirst().status()).isEqualTo("PARTIALLY_CLEARED");
        // Final shipment smaller than the rest of the authorization: remaining hold released.
        var r2 = ingest(pres(pan, a.authCode(), "627512000001", 5_000, "5999", 2, 2));
        assertThat(r2.lines().getFirst().outcome()).isEqualTo("MATCHED");
        var end = cards.account(c.accountId());
        assertThat(end.heldMinor()).isZero();
        assertThat(end.ledgerBalanceMinor()).isEqualTo(2_000);
        assertThat(end.holds().getFirst().status()).isEqualTo("CLEARED");
    }

    @Test
    void amountToleranceDependsOnMerchantCategory() {
        String pan = newPan();
        var c = issue(pan, 100_000, 0, "ACTIVE");
        // Restaurant: a 15% tip is within the 20% tolerance.
        var meal = auths.authorize(auth(c, ref(), 10_000, "5812"));
        assertThat(ingest(pres(pan, meal.authCode(), "NOMATCHRRN01", 11_500, "5812", 1, 1)).lines().getFirst()
            .outcome()).isEqualTo("MATCHED");
        // Grocery: no tolerance; still matched on approval code + RRN but flagged.
        var shop = auths.authorize(auth(c, ref(), 10_000, "5411"));
        assertThat(ingest(pres(pan, shop.authCode(), "627512000001", 11_500, "5411", 1, 1)).lines().getFirst()
            .outcome()).isEqualTo("MATCHED_OVER_TOLERANCE");
    }

    @Test
    void forcePostAndUnknownCard() {
        String pan = newPan();
        var c = issue(pan, 10_000, 0, "ACTIVE");
        var r = ingest(pres(pan, "999999", "000000000000", 1_234, "5411", 1, 1),
            pres("9990019999999999", "111111", "000000000000", 500, "5411", 1, 1));
        assertThat(r.lines()).extracting(ClearingService.LineResult::outcome)
            .containsExactly("FORCE_POST", "UNKNOWN_CARD");
        assertThat(ledgerBalance(c)).isEqualTo(8_766);
        assertThat(ledger.trialBalance().balanced()).isTrue();
        assertThat(ledger.trialBalance().materialisedBalancesMatch()).isTrue();
    }

    @Test
    void duplicateFilesAndRecordsAreNotPostedTwice() {
        String pan = newPan();
        var c = issue(pan, 10_000, 0, "ACTIVE");
        var a = auths.authorize(auth(c, ref(), 1_000));
        Pres p = pres(pan, a.authCode(), "627512000001", 1_000, "5411", 1, 1);
        LocalDate d = LocalDate.now(clock);
        String f = file(d, List.of(p.line(d)), 1_000);
        clearing.ingest(f);
        assertThatThrownBy(() -> clearing.ingest(f)).isInstanceOf(ApiException.class)
            .hasMessageContaining("already ingested");
        // Same record inside a different file.
        var again = clearing.ingest(file(d, List.of(p.line(d)), 1_000));
        assertThat(again.lines().getFirst().outcome()).isEqualTo("DUPLICATE_RECORD");
        assertThat(ledgerBalance(c)).isEqualTo(9_000);
    }

    @Test
    void lateSettlementAfterHoldExpiryStillMatches() {
        String pan = newPan();
        var c = issue(pan, 10_000, 0, "ACTIVE");
        var a = auths.authorize(auth(c, ref(), 2_000));
        clock.advance(java.time.Duration.ofDays(9));
        auths.expireHolds(java.time.OffsetDateTime.now(clock));
        var r = ingest(pres(pan, a.authCode(), "627512000001", 2_000, "5411", 1, 1));
        assertThat(r.lines().getFirst().outcome()).isEqualTo("MATCHED_EXPIRED_HOLD");
        assertThat(cards.account(c.accountId()).availableMinor()).isEqualTo(8_000);
    }
}
