package io.github.eunini.issuer.cards;

import static io.github.eunini.issuer.ledger.LedgerService.Leg.credit;
import static io.github.eunini.issuer.ledger.LedgerService.Leg.debit;

import io.github.eunini.issuer.cards.CardModels.*;
import io.github.eunini.issuer.common.ApiException;
import io.github.eunini.issuer.common.Audit;
import io.github.eunini.issuer.ledger.LedgerService;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CardService {

    private final JdbcClient jdbc;
    private final LedgerService ledger;
    private final Audit audit;
    private final Clock clock;

    public CardService(JdbcClient jdbc, LedgerService ledger, Audit audit, Clock clock) {
        this.jdbc = jdbc;
        this.ledger = ledger;
        this.audit = audit;
        this.clock = clock;
    }

    /** Create account + ledger account + card, funding the opening balance. Idempotent per panRef. */
    @Transactional
    public List<ImportResult> importCards(List<CardImport> cards) {
        List<ImportResult> out = new ArrayList<>();
        OffsetDateTime now = OffsetDateTime.now(clock);
        for (CardImport c : cards) {
            Optional<long[]> existing = jdbc.sql("SELECT id, account_id FROM cards WHERE pan_ref = ?")
                .param(c.panRef())
                .query((rs, i) -> new long[] {rs.getLong(1), rs.getLong(2)})
                .optional();
            if (existing.isPresent()) {
                out.add(new ImportResult(c.panRef(), existing.get()[0], existing.get()[1], false));
                continue;
            }
            long ledgerId = ledger.createAccount("CARDHOLDER-" + c.panRef(), "CARDHOLDER", LedgerService.Side.C,
                c.currency());
            var kh = new GeneratedKeyHolder();
            jdbc.sql("""
                    INSERT INTO card_accounts (holder_name, currency, credit_limit_minor, ledger_account_id, created_at)
                    VALUES (?, ?, ?, ?, ?)""")
                .params(c.holderName(), c.currency(), c.creditLimitMinor(), ledgerId, now)
                .update(kh, "id");
            long accountId = kh.getKey().longValue();
            kh = new GeneratedKeyHolder();
            jdbc.sql("""
                    INSERT INTO cards (account_id, pan_ref, last4, expiry, status, pvv, pvki, service_code, psn, cvn,
                                       per_txn_limit_minor, daily_cash_limit_minor, daily_txn_count_limit, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""")
                .params(accountId, c.panRef(), c.last4(), c.expiry(), c.status(), c.pvv(), c.pvki(), c.serviceCode(),
                    c.psn(), c.cvn(), c.perTxnLimitMinor(), c.dailyCashLimitMinor(), c.dailyTxnCountLimit(), now)
                .update(kh, "id");
            long cardId = kh.getKey().longValue();
            if (c.openingBalanceMinor() > 0) {
                ledger.post("DEPOSIT", "OPENING:" + c.panRef(), "Opening balance",
                    List.of(debit(ledger.internal("ISSUER_CASH", c.currency()), c.openingBalanceMinor()),
                        credit(ledgerId, c.openingBalanceMinor())));
            }
            audit.record("CARD", cardId, "ISSUED", "last4=" + c.last4() + " status=" + c.status(), "import");
            out.add(new ImportResult(c.panRef(), cardId, accountId, true));
        }
        return out;
    }

    public List<CardProfile> snapshot() {
        return jdbc.sql("""
                SELECT c.id, c.account_id, c.pan_ref, c.last4, c.expiry, c.status, c.pvv, c.pvki, c.service_code,
                       c.psn, c.cvn, a.currency, c.per_txn_limit_minor, c.daily_cash_limit_minor,
                       c.daily_txn_count_limit
                  FROM cards c JOIN card_accounts a ON a.id = c.account_id
                 ORDER BY c.id""")
            .query((rs, i) -> new CardProfile(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getString(4),
                rs.getString(5), rs.getString(6), rs.getString(7), rs.getInt(8), rs.getString(9), rs.getString(10),
                rs.getInt(11), rs.getString(12), rs.getLong(13), rs.getLong(14), rs.getInt(15)))
            .list();
    }

    @Transactional
    public void changeStatus(long cardId, StatusChange s, String actor) {
        int n = jdbc.sql("UPDATE cards SET status = ?, updated_at = ? WHERE id = ?")
            .params(s.status(), OffsetDateTime.now(clock), cardId).update();
        if (n == 0) {
            throw ApiException.notFound("card " + cardId);
        }
        audit.record("CARD", cardId, "STATUS_" + s.status(), s.reason(), actor);
    }

    @Transactional
    public long deposit(long accountId, Deposit d) {
        var acct = jdbc.sql("SELECT ledger_account_id, currency FROM card_accounts WHERE id = ? FOR UPDATE")
            .param(accountId)
            .query((rs, i) -> new Object[] {rs.getLong(1), rs.getString(2)})
            .optional()
            .orElseThrow(() -> ApiException.notFound("account " + accountId));
        long ledgerId = (Long) acct[0];
        String ccy = (String) acct[1];
        return ledger.post("DEPOSIT", "DEPOSIT:" + accountId + ":" + d.reference(), "Deposit " + d.reference(),
            List.of(debit(ledger.internal("ISSUER_CASH", ccy), d.amountMinor()), credit(ledgerId, d.amountMinor())))
            .entryId();
    }

    @Transactional(readOnly = true)
    public AccountView account(long accountId) {
        var a = jdbc.sql("""
                SELECT a.holder_name, a.currency, a.credit_limit_minor, a.held_minor, a.ledger_account_id,
                       l.balance_minor
                  FROM card_accounts a JOIN ledger_accounts l ON l.id = a.ledger_account_id
                 WHERE a.id = ?""")
            .param(accountId)
            .query((rs, i) -> new Object[] {rs.getString(1), rs.getString(2), rs.getLong(3), rs.getLong(4),
                rs.getLong(5), rs.getLong(6)})
            .optional()
            .orElseThrow(() -> ApiException.notFound("account " + accountId));
        long credit = (Long) a[2];
        long held = (Long) a[3];
        long balance = (Long) a[5];
        List<HoldView> holds = jdbc.sql("""
                SELECT auth_ref, amount_minor, held_minor, cleared_minor, status, source, merchant_name, auth_code,
                       overdraft, expires_at
                  FROM authorizations
                 WHERE account_id = ? AND status <> 'INCREMENTAL'
                 ORDER BY id DESC
                 LIMIT 50""")
            .param(accountId)
            .query((rs, i) -> new HoldView(rs.getString(1), rs.getLong(2), rs.getLong(3), rs.getLong(4),
                rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8), rs.getBoolean(9),
                rs.getObject(10, OffsetDateTime.class)))
            .list();
        return new AccountView(accountId, (String) a[0], (String) a[1], balance, held, credit,
            balance + credit - held, holds, ledger.recentPostings((Long) a[4], 20));
    }
}
