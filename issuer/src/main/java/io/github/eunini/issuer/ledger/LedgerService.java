package io.github.eunini.issuer.ledger;

import io.github.eunini.issuer.common.ApiException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Double-entry ledger. Every financial event is one journal entry whose
 * debit and credit legs sum to the same amount. Entries are immutable and
 * keyed by a business reference, which makes posting idempotent: posting
 * the same reference twice returns the first entry and changes nothing.
 *
 * Balances are materialised on {@code ledger_accounts} in the same
 * transaction (on the account's normal side), and can be re-derived from
 * postings at any time ({@link #trialBalance()}).
 */
@Service
public class LedgerService {

    public enum Side { D, C }

    public record Leg(long ledgerAccountId, Side side, long amountMinor) {
        public static Leg debit(long account, long amount) {
            return new Leg(account, Side.D, amount);
        }

        public static Leg credit(long account, long amount) {
            return new Leg(account, Side.C, amount);
        }
    }

    public record PostResult(long entryId, boolean created) {}

    private final JdbcClient jdbc;
    private final Clock clock;
    private final Map<String, Long> internalIds = new ConcurrentHashMap<>();

    public LedgerService(JdbcClient jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    /** Id of an internal account such as {@code NETWORK_SETTLEMENT-840}. */
    public long internal(String kind, String currency) {
        String code = kind + "-" + currency;
        return internalIds.computeIfAbsent(code, c -> jdbc.sql("SELECT id FROM ledger_accounts WHERE code = ?")
            .param(c)
            .query(Long.class)
            .optional()
            .orElseThrow(() -> ApiException.rule("NO_LEDGER_ACCOUNT", "no internal account " + c)));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public long createAccount(String code, String kind, Side normalSide, String currency) {
        var kh = new GeneratedKeyHolder();
        jdbc.sql("INSERT INTO ledger_accounts (code, kind, normal_side, currency) VALUES (?, ?, ?, ?)")
            .params(code, kind, normalSide.name(), currency)
            .update(kh, "id");
        return kh.getKey().longValue();
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public PostResult post(String entryType, String reference, String description, List<Leg> legs) {
        if (legs.size() < 2) {
            throw new IllegalArgumentException("an entry needs at least two legs");
        }
        long debits = 0;
        long credits = 0;
        for (Leg l : legs) {
            if (l.amountMinor() <= 0) {
                throw new IllegalArgumentException("leg amounts must be positive");
            }
            if (l.side() == Side.D) {
                debits = Math.addExact(debits, l.amountMinor());
            } else {
                credits = Math.addExact(credits, l.amountMinor());
            }
        }
        if (debits != credits) {
            throw new IllegalArgumentException("unbalanced entry: debits " + debits + " != credits " + credits);
        }
        Optional<Long> existing = jdbc.sql("SELECT id FROM journal_entries WHERE reference = ?")
            .param(reference).query(Long.class).optional();
        if (existing.isPresent()) {
            return new PostResult(existing.get(), false);
        }
        var kh = new GeneratedKeyHolder();
        jdbc.sql("INSERT INTO journal_entries (entry_type, reference, description, created_at) VALUES (?, ?, ?, ?)")
            .params(entryType, reference, description, OffsetDateTime.now(clock))
            .update(kh, "id");
        long entryId = kh.getKey().longValue();
        // Update balances in a fixed (id) order so concurrent entries touching
        // the same accounts cannot deadlock.
        List<Leg> ordered = new ArrayList<>(legs);
        ordered.sort(Comparator.comparingLong(Leg::ledgerAccountId));
        for (Leg l : ordered) {
            jdbc.sql("INSERT INTO postings (entry_id, ledger_account_id, direction, amount_minor) VALUES (?, ?, ?, ?)")
                .params(entryId, l.ledgerAccountId(), l.side().name(), l.amountMinor())
                .update();
            int n = jdbc.sql("""
                    UPDATE ledger_accounts
                       SET balance_minor = balance_minor + CASE WHEN normal_side = ? THEN ? ELSE ? END
                     WHERE id = ?""")
                .params(l.side().name(), l.amountMinor(), -l.amountMinor(), l.ledgerAccountId())
                .update();
            if (n != 1) {
                throw new IllegalArgumentException("unknown ledger account " + l.ledgerAccountId());
            }
        }
        return new PostResult(entryId, true);
    }

    public long balance(long ledgerAccountId) {
        return jdbc.sql("SELECT balance_minor FROM ledger_accounts WHERE id = ?")
            .param(ledgerAccountId).query(Long.class).single();
    }

    public record AccountLine(String code, String kind, String normalSide, long debitsMinor, long creditsMinor,
                              long balanceMinor, long materialisedBalanceMinor) {}

    public record TrialBalance(List<AccountLine> accounts, long totalDebitsMinor, long totalCreditsMinor,
                               boolean balanced, boolean materialisedBalancesMatch) {}

    /** Recompute every balance from postings and compare with the materialised values. */
    @Transactional(readOnly = true)
    public TrialBalance trialBalance() {
        List<AccountLine> lines = jdbc.sql("""
                SELECT a.code, a.kind, a.normal_side, a.balance_minor,
                       COALESCE(SUM(CASE WHEN p.direction = 'D' THEN p.amount_minor END), 0) AS debits,
                       COALESCE(SUM(CASE WHEN p.direction = 'C' THEN p.amount_minor END), 0) AS credits
                  FROM ledger_accounts a
                  LEFT JOIN postings p ON p.ledger_account_id = a.id
                 GROUP BY a.id, a.code, a.kind, a.normal_side, a.balance_minor
                 ORDER BY a.id""")
            .query((rs, i) -> {
                long d = rs.getLong("debits");
                long c = rs.getLong("credits");
                String side = rs.getString("normal_side");
                long derived = "D".equals(side) ? d - c : c - d;
                return new AccountLine(rs.getString("code"), rs.getString("kind"), side, d, c, derived,
                    rs.getLong("balance_minor"));
            })
            .list();
        long td = lines.stream().mapToLong(AccountLine::debitsMinor).sum();
        long tc = lines.stream().mapToLong(AccountLine::creditsMinor).sum();
        boolean match = lines.stream().allMatch(l -> l.balanceMinor() == l.materialisedBalanceMinor());
        return new TrialBalance(lines, td, tc, td == tc, match);
    }

    public record PostingView(String entryType, String reference, String description, String direction,
                              long amountMinor, OffsetDateTime createdAt) {}

    public List<PostingView> recentPostings(long ledgerAccountId, int limit) {
        return jdbc.sql("""
                SELECT e.entry_type, e.reference, e.description, p.direction, p.amount_minor, e.created_at
                  FROM postings p JOIN journal_entries e ON e.id = p.entry_id
                 WHERE p.ledger_account_id = ?
                 ORDER BY p.id DESC
                 LIMIT ?""")
            .params(ledgerAccountId, limit)
            .query((rs, i) -> new PostingView(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getLong(5), rs.getObject(6, OffsetDateTime.class)))
            .list();
    }
}
