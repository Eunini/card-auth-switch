package io.github.eunini.issuer;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.eunini.issuer.auth.AuthModels.*;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AuthorizationServiceTest extends IntegrationTest {

    @Test
    void approvesWithinOpenToBuyAndDeclinesInsufficientFunds() {
        var c = issue(10_000);
        var ok = auths.authorize(auth(c, ref(), 6_000));
        assertThat(ok.approved()).isTrue();
        assertThat(ok.responseCode()).isEqualTo("00");
        assertThat(ok.authCode()).hasSize(6);
        assertThat(ok.availableMinor()).isEqualTo(4_000);
        var no = auths.authorize(auth(c, ref(), 4_001));
        assertThat(no.approved()).isFalse();
        assertThat(no.responseCode()).isEqualTo("51");
        assertThat(available(c.accountId())).isEqualTo(4_000);
    }

    @Test
    void creditLimitCountsTowardsOpenToBuy() {
        var c = issue(newPan(), 0, 50_000, "ACTIVE");
        assertThat(auths.authorize(auth(c, ref(), 50_000)).approved()).isTrue();
        assertThat(auths.authorize(auth(c, ref(), 1)).responseCode()).isEqualTo("51");
    }

    @Test
    void sameAuthRefIsIdempotent() {
        var c = issue(10_000);
        String r = ref();
        var a = auths.authorize(auth(c, r, 3_000));
        var b = auths.authorize(auth(c, r, 3_000));
        assertThat(b.authCode()).isEqualTo(a.authCode());
        assertThat(available(c.accountId())).isEqualTo(7_000);
    }

    @Test
    void cardStatusAndUnknownCard() {
        var lost = issue(newPan(), 10_000, 0, "LOST");
        assertThat(auths.authorize(auth(lost, ref(), 100)).responseCode()).isEqualTo("41");
        var c = issue(10_000);
        var wrongAccount = new AuthRequest(ref(), c.cardId(), c.accountId() + 999, 100, "840", "PURCHASE", "5411",
            null, null, null, null, null, null, null, null);
        assertThat(auths.authorize(wrongAccount).responseCode()).isEqualTo("14");
        assertThat(auths.authorize(auth(c, ref(), 0)).responseCode()).isEqualTo("13");
    }

    @Test
    void incrementalAuthorizationGrowsTheOriginalHold() {
        var c = issue(50_000);
        String hotel = ref();
        assertThat(auths.authorize(auth(c, hotel, 20_000, "7011")).approved()).isTrue();
        var inc = new AuthRequest(ref(), c.cardId(), c.accountId(), 15_000, "840", "PURCHASE", "7011", null, null,
            null, null, null, null, null, hotel);
        assertThat(auths.authorize(inc).approved()).isTrue();
        var view = cards.account(c.accountId());
        var hold = view.holds().stream().filter(h -> h.authRef().equals(hotel)).findFirst().orElseThrow();
        assertThat(hold.amountMinor()).isEqualTo(35_000);
        assertThat(hold.heldMinor()).isEqualTo(35_000);
        // Lodging holds last 30 days, not 7.
        assertThat(hold.expiresAt()).isAfter(OffsetDateTime.now(clock).plusDays(29));
        var tooMuch = new AuthRequest(ref(), c.cardId(), c.accountId(), 15_001, "840", "PURCHASE", "7011", null,
            null, null, null, null, null, null, hotel);
        assertThat(auths.authorize(tooMuch).responseCode()).isEqualTo("51");
    }

    @Test
    void partialThenFullReversalAreIdempotent() {
        var c = issue(10_000);
        String r = ref();
        auths.authorize(auth(c, r, 8_000));
        assertThat(auths.reverse(new ReversalRequest(r + ":5000", r, 5_000L, "REQUEST")).status())
            .isEqualTo("PARTIALLY_REVERSED");
        assertThat(available(c.accountId())).isEqualTo(5_000);
        // Repeat of the same partial reversal changes nothing.
        assertThat(auths.reverse(new ReversalRequest(r + ":5000", r, 5_000L, "REQUEST")).status())
            .isEqualTo("PARTIALLY_REVERSED");
        assertThat(available(c.accountId())).isEqualTo(5_000);
        assertThat(auths.reverse(new ReversalRequest(r + ":FULL", r, null, "REQUEST")).status()).isEqualTo("REVERSED");
        assertThat(available(c.accountId())).isEqualTo(10_000);
        assertThat(auths.reverse(new ReversalRequest(r + ":FULL2", r, null, "REQUEST")).status())
            .isEqualTo("ALREADY_REVERSED");
        assertThat(auths.reverse(new ReversalRequest("nope", "unknown-ref", null, "REQUEST")).status())
            .isEqualTo("NOT_FOUND");
    }

    @Test
    void standInAdviceIsHonouredEvenIfItOverdraws() {
        var c = issue(1_000);
        String r = ref();
        var adv = new AdviceRequest("STIP-" + r, "SWITCH_STIP", "00", "S12345", auth(c, r, 5_000));
        assertThat(auths.advice(adv).status()).isEqualTo("RECORDED_OVERDRAFT");
        assertThat(auths.advice(adv).status()).isEqualTo("DUPLICATE");
        assertThat(available(c.accountId())).isEqualTo(-4_000);
        var hold = cards.account(c.accountId()).holds().getFirst();
        assertThat(hold.source()).isEqualTo("STIP_ADVICE");
        assertThat(hold.overdraft()).isTrue();
        assertThat(hold.authCode()).isEqualTo("S12345");
    }

    @Test
    void timeoutRaceAdviceOverridesIssuerDecline() {
        // The issuer declined (51) but its answer arrived after the switch's
        // deadline; the switch stood in and approved. The advice wins.
        var c = issue(1_000);
        String r = ref();
        assertThat(auths.authorize(auth(c, r, 2_000)).responseCode()).isEqualTo("51");
        var adv = new AdviceRequest("STIP-" + r, "SWITCH_STIP", "00", "S00001", auth(c, r, 2_000));
        assertThat(auths.advice(adv).status()).isEqualTo("RECONCILED_TO_APPROVED");
        assertThat(available(c.accountId())).isEqualTo(-1_000);
    }

    @Test
    void lateIssuerApprovalPlusStandInAdviceGivesOneHoldWithTheMerchantsCode() {
        // The issuer hung, the switch stood in (code S00002), then the issuer
        // woke up and approved the same request with its own code.
        var c = issue(10_000);
        String r = ref();
        var late = auths.authorize(auth(c, r, 3_000));
        assertThat(late.approved()).isTrue();
        var adv = new AdviceRequest("STIP-" + r, "SWITCH_STIP", "00", "S00002", auth(c, r, 3_000));
        assertThat(auths.advice(adv).status()).isEqualTo("RECONCILED_AUTH_CODE");
        var v = cards.account(c.accountId());
        assertThat(v.heldMinor()).isEqualTo(3_000);
        assertThat(v.holds().getFirst().authCode()).isEqualTo("S00002");
    }

    @Test
    void holdsExpire() {
        var c = issue(10_000);
        auths.authorize(auth(c, ref(), 4_000));
        assertThat(auths.expireHolds(OffsetDateTime.now(clock).plusDays(6))).isZero();
        clock.advance(Duration.ofDays(8));
        assertThat(auths.expireHolds(OffsetDateTime.now(clock))).isGreaterThanOrEqualTo(1);
        assertThat(available(c.accountId())).isEqualTo(10_000);
    }

    @Test
    void concurrentAuthorizationsNeverOversell() throws Exception {
        var c = issue(20_000);
        ExecutorService pool = Executors.newFixedThreadPool(16);
        AtomicInteger approved = new AtomicInteger();
        List<Future<?>> fs = new ArrayList<>();
        for (int t = 0; t < 16; t++) {
            fs.add(pool.submit(() -> {
                for (int i = 0; i < 25; i++) {
                    if (auths.authorize(auth(c, ref(), 100)).approved()) {
                        approved.incrementAndGet();
                    }
                }
            }));
        }
        for (Future<?> f : fs) {
            f.get();
        }
        pool.shutdown();
        assertThat(approved.get()).isEqualTo(200);
        assertThat(available(c.accountId())).isZero();
        assertThat(cards.account(c.accountId()).heldMinor()).isEqualTo(20_000);
    }
}
