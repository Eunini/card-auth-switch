package io.github.eunini.issuer.auth;

import io.github.eunini.issuer.auth.AuthModels.*;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Open-to-buy decisions and holds.
 *
 * <p>Concurrency: every operation that changes an account's holds first
 * takes a row lock on {@code card_accounts} ({@code SELECT ... FOR UPDATE}),
 * so balance checks and hold placement for one account are serialised while
 * different accounts proceed in parallel. Idempotency checks happen after the
 * lock, so concurrent duplicates of the same request also serialise.
 *
 * <p>available = ledger balance + credit limit - outstanding holds.
 */
@Service
public class AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);
    /** Lodging, car rental, cruise: holds live longer (estimated amounts, incrementals). */
    private static final Set<String> EXTENDED_HOLD_MCC = Set.of("7011", "7512", "4411");

    private final JdbcClient jdbc;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Duration holdTtl;
    private final Duration extendedHoldTtl;

    public AuthorizationService(JdbcClient jdbc, Clock clock,
                                @Value("${issuer.hold-days:7}") int holdDays,
                                @Value("${issuer.extended-hold-days:30}") int extendedHoldDays) {
        this.jdbc = jdbc;
        this.clock = clock;
        this.holdTtl = Duration.ofDays(holdDays);
        this.extendedHoldTtl = Duration.ofDays(extendedHoldDays);
    }

    public record Account(long id, String currency, long creditLimit, long held, long balance) {
        public long available() {
            return balance + creditLimit - held;
        }
    }

    record Card(long id, long accountId, String status) {}

    record Auth(long id, String authRef, long cardId, long accountId, long amount, long held, long cleared,
                String status, String responseCode, String authCode) {}

    private Optional<Card> card(long cardId) {
        return jdbc.sql("SELECT id, account_id, status FROM cards WHERE id = ?")
            .param(cardId)
            .query((rs, i) -> new Card(rs.getLong(1), rs.getLong(2), rs.getString(3)))
            .optional();
    }

    /** Lock the account row and read its balance. */
    public Account lockAccount(long accountId) {
        jdbc.sql("SELECT id FROM card_accounts WHERE id = ? FOR UPDATE").param(accountId).query(Long.class).single();
        return jdbc.sql("""
                SELECT a.id, a.currency, a.credit_limit_minor, a.held_minor, l.balance_minor
                  FROM card_accounts a JOIN ledger_accounts l ON l.id = a.ledger_account_id
                 WHERE a.id = ?""")
            .param(accountId)
            .query((rs, i) -> new Account(rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getLong(4),
                rs.getLong(5)))
            .single();
    }

    Optional<Auth> findAuth(String authRef) {
        return jdbc.sql("""
                SELECT id, auth_ref, card_id, account_id, amount_minor, held_minor, cleared_minor, status,
                       response_code, auth_code
                  FROM authorizations WHERE auth_ref = ?""")
            .param(authRef)
            .query((rs, i) -> new Auth(rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getLong(4), rs.getLong(5),
                rs.getLong(6), rs.getLong(7), rs.getString(8), rs.getString(9), rs.getString(10)))
            .optional();
    }

    private void adjustHeld(long accountId, long delta) {
        jdbc.sql("UPDATE card_accounts SET held_minor = held_minor + ? WHERE id = ?").params(delta, accountId).update();
    }

    private String newAuthCode() {
        return String.format("%06d", random.nextInt(1_000_000));
    }

    private OffsetDateTime expiry(String mcc, OffsetDateTime now) {
        return now.plus(mcc != null && EXTENDED_HOLD_MCC.contains(mcc) ? extendedHoldTtl : holdTtl);
    }

    private long insertAuth(AuthRequest r, long accountId, Long parentId, long amount, long held, String authCode,
                            String rc, String status, String source, boolean overdraft) {
        OffsetDateTime now = OffsetDateTime.now(clock);
        var kh = new GeneratedKeyHolder();
        jdbc.sql("""
                INSERT INTO authorizations (auth_ref, card_id, account_id, parent_auth_id, amount_minor, held_minor,
                    currency, txn_type, mcc, merchant_name, terminal_id, rrn, stan, auth_code, response_code, status,
                    source, overdraft, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""")
            .params(r.authRef(), r.cardId(), accountId, parentId, amount, held, r.currency(), r.txnType(), r.mcc(),
                truncate(r.merchantName(), 64), r.terminalId(), r.rrn(), r.stan(), authCode, rc, status, source,
                overdraft, now, "ACTIVE".equals(status) ? expiry(r.mcc(), now) : now)
            .update(kh, "id");
        return kh.getKey().longValue();
    }

    private static String truncate(String s, int n) {
        return s == null || s.length() <= n ? s : s.substring(0, n);
    }

    private static String cardDecline(String status) {
        return switch (status) {
            case "ACTIVE" -> null;
            case "LOST" -> "41";
            case "STOLEN" -> "43";
            case "BLOCKED" -> "62";
            default -> "05";
        };
    }

    @Transactional
    public AuthResponse authorize(AuthRequest r) {
        if (r.amountMinor() <= 0) {
            return new AuthResponse(false, "13", null, null);
        }
        Optional<Card> card = card(r.cardId());
        if (card.isEmpty() || card.get().accountId() != r.accountId()) {
            return new AuthResponse(false, "14", null, null);
        }
        Account acct = lockAccount(r.accountId());
        Optional<Auth> existing = findAuth(r.authRef());
        if (existing.isPresent()) {
            // Idempotent: the same request (e.g. a switch retry) gets the same answer.
            Auth e = existing.get();
            boolean ok = "00".equals(e.responseCode());
            return new AuthResponse(ok, e.responseCode(), ok ? e.authCode() : null, acct.available());
        }
        if (r.incrementalOf() != null) {
            return incremental(r, acct);
        }
        String decline = cardDecline(card.get().status());
        if (decline == null && !acct.currency().equals(r.currency())) {
            decline = "12";
        }
        if (decline == null && r.amountMinor() > acct.available()) {
            decline = "51";
        }
        if (decline != null) {
            insertAuth(r, acct.id(), null, r.amountMinor(), 0, null, decline, "DECLINED", "ONLINE", false);
            return new AuthResponse(false, decline, null, acct.available());
        }
        String code = newAuthCode();
        insertAuth(r, acct.id(), null, r.amountMinor(), r.amountMinor(), code, "00", "ACTIVE", "ONLINE", false);
        adjustHeld(acct.id(), r.amountMinor());
        return new AuthResponse(true, "00", code, acct.available() - r.amountMinor());
    }

    /** Incremental authorization: grow the original hold (hotel stay extended, etc.). */
    private AuthResponse incremental(AuthRequest r, Account acct) {
        Auth parent = findAuth(r.incrementalOf()).orElse(null);
        if (parent == null || parent.accountId() != acct.id()
            || !Set.of("ACTIVE", "PARTIALLY_CLEARED").contains(parent.status())) {
            insertAuth(r, acct.id(), null, r.amountMinor(), 0, null, "12", "DECLINED", "ONLINE", false);
            return new AuthResponse(false, "12", null, acct.available());
        }
        if (r.amountMinor() > acct.available()) {
            insertAuth(r, acct.id(), parent.id(), r.amountMinor(), 0, null, "51", "DECLINED", "ONLINE", false);
            return new AuthResponse(false, "51", null, acct.available());
        }
        insertAuth(r, acct.id(), parent.id(), r.amountMinor(), 0, parent.authCode(), "00", "INCREMENTAL", "ONLINE",
            false);
        jdbc.sql("""
                UPDATE authorizations
                   SET amount_minor = amount_minor + ?, held_minor = held_minor + ?, expires_at = ?
                 WHERE id = ?""")
            .params(r.amountMinor(), r.amountMinor(), expiry(r.mcc(), OffsetDateTime.now(clock)), parent.id())
            .update();
        adjustHeld(acct.id(), r.amountMinor());
        return new AuthResponse(true, "00", parent.authCode(), acct.available() - r.amountMinor());
    }

    /**
     * Advice of a decision already given to the cardholder (switch stand-in or
     * acquirer). Approvals must be honoured even if they overdraw the account.
     */
    @Transactional
    public StatusResponse advice(AdviceRequest a) {
        if (jdbc.sql("SELECT COUNT(*) FROM advices WHERE advice_id = ?").param(a.adviceId()).query(Long.class)
            .single() > 0) {
            return new StatusResponse("DUPLICATE");
        }
        AuthRequest r = a.auth();
        Optional<Card> card = card(r.cardId());
        if (card.isEmpty()) {
            return new StatusResponse("UNKNOWN_CARD");
        }
        Account acct = lockAccount(card.get().accountId());
        String source = "SWITCH_STIP".equals(a.source()) ? "STIP_ADVICE" : "ACQUIRER_ADVICE";
        boolean approved = "00".equals(a.responseCode());
        Optional<Auth> existing = findAuth(r.authRef());
        String status;
        if (existing.isPresent()) {
            // Timeout race: the issuer did process the request but the switch
            // gave up waiting and stood in. The switch's answer is what the
            // cardholder saw, so it wins.
            Auth e = existing.get();
            if (approved && "DECLINED".equals(e.status())) {
                jdbc.sql("""
                        UPDATE authorizations SET status = 'ACTIVE', held_minor = ?, response_code = '00',
                               auth_code = ?, source = ?, overdraft = ?, expires_at = ? WHERE id = ?""")
                    .params(e.amount(), a.authCode(), source, e.amount() > acct.available(),
                        expiry(r.mcc(), OffsetDateTime.now(clock)), e.id())
                    .update();
                adjustHeld(acct.id(), e.amount());
                status = "RECONCILED_TO_APPROVED";
            } else if (!approved && "ACTIVE".equals(e.status())) {
                jdbc.sql("UPDATE authorizations SET status = 'DECLINED', held_minor = 0, response_code = ? WHERE id = ?")
                    .params(a.responseCode(), e.id()).update();
                adjustHeld(acct.id(), -e.held());
                status = "RECONCILED_TO_DECLINED";
            } else {
                status = "ALREADY_KNOWN";
            }
            log.info("advice {} for existing auth {}: {}", a.adviceId(), r.authRef(), status);
        } else if (approved) {
            boolean overdraft = r.amountMinor() > acct.available();
            insertAuth(r, acct.id(), null, r.amountMinor(), r.amountMinor(), a.authCode(), "00", "ACTIVE", source,
                overdraft);
            adjustHeld(acct.id(), r.amountMinor());
            status = overdraft ? "RECORDED_OVERDRAFT" : "RECORDED";
        } else {
            insertAuth(r, acct.id(), null, r.amountMinor(), 0, null, a.responseCode(), "DECLINED", source, false);
            status = "RECORDED";
        }
        jdbc.sql("INSERT INTO advices (advice_id, source, auth_ref, response_code, created_at) VALUES (?, ?, ?, ?, ?)")
            .params(a.adviceId(), a.source(), r.authRef(), a.responseCode(), OffsetDateTime.now(clock))
            .update();
        return new StatusResponse(status);
    }

    /** Full or partial reversal, idempotent by reversalRef. */
    @Transactional
    public StatusResponse reverse(ReversalRequest r) {
        Optional<String> done = jdbc.sql("SELECT status FROM reversals WHERE reversal_ref = ?")
            .param(r.reversalRef()).query(String.class).optional();
        if (done.isPresent()) {
            return new StatusResponse(done.get());
        }
        Optional<Auth> found = findAuth(r.authRef());
        if (found.isEmpty()) {
            // Not recorded: if the original shows up later (out-of-order
            // delivery) a retried reversal can still apply.
            return new StatusResponse("NOT_FOUND");
        }
        lockAccount(found.get().accountId());
        Auth a = findAuth(r.authRef()).orElseThrow();
        String status;
        long release = 0;
        Long replacement = r.replacementAmountMinor();
        switch (a.status()) {
            case "DECLINED" -> status = "NOTHING_TO_REVERSE";
            case "REVERSED" -> status = "ALREADY_REVERSED";
            case "CLEARED" -> status = "ALREADY_CLEARED";
            default -> {
                if (replacement == null || replacement <= 0) {
                    release = a.held();
                    jdbc.sql("UPDATE authorizations SET status = 'REVERSED', held_minor = 0 WHERE id = ?")
                        .param(a.id()).update();
                    status = "REVERSED";
                } else if (replacement >= a.amount()) {
                    status = "NOTHING_TO_REVERSE";
                } else {
                    long newHeld = Math.max(replacement - a.cleared(), 0);
                    release = Math.max(a.held() - newHeld, 0);
                    jdbc.sql("UPDATE authorizations SET amount_minor = ?, held_minor = ? WHERE id = ?")
                        .params(replacement, a.held() - release, a.id()).update();
                    status = "PARTIALLY_REVERSED";
                }
            }
        }
        if (release > 0) {
            adjustHeld(a.accountId(), -release);
        }
        jdbc.sql("""
                INSERT INTO reversals (reversal_ref, auth_ref, replacement_amount_minor, status, created_at)
                VALUES (?, ?, ?, ?, ?)""")
            .params(r.reversalRef(), r.authRef(), replacement, status, OffsetDateTime.now(clock))
            .update();
        return new StatusResponse(status);
    }

    /** Release holds whose validity has passed without a presentment. */
    @Transactional
    public int expireHolds(OffsetDateTime asOf) {
        List<long[]> due = jdbc.sql("""
                SELECT id, account_id FROM authorizations
                 WHERE status IN ('ACTIVE', 'PARTIALLY_CLEARED') AND expires_at < ?
                 ORDER BY account_id, id""")
            .param(asOf)
            .query((rs, i) -> new long[] {rs.getLong(1), rs.getLong(2)})
            .list();
        int n = 0;
        for (long[] d : due) {
            lockAccount(d[1]);
            Long held = jdbc.sql("""
                    SELECT held_minor FROM authorizations
                     WHERE id = ? AND status IN ('ACTIVE', 'PARTIALLY_CLEARED')""")
                .param(d[0]).query(Long.class).optional().orElse(null);
            if (held == null) {
                continue;
            }
            jdbc.sql("UPDATE authorizations SET status = 'EXPIRED', held_minor = 0 WHERE id = ?").param(d[0]).update();
            adjustHeld(d[1], -held);
            n++;
        }
        if (n > 0) {
            log.info("expired {} holds", n);
        }
        return n;
    }

    @Scheduled(fixedDelayString = "${issuer.hold-expiry-interval-ms:60000}")
    @Transactional
    public void scheduledExpiry() {
        expireHolds(OffsetDateTime.now(clock));
    }
}
