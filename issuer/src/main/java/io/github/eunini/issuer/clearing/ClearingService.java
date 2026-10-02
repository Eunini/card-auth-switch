package io.github.eunini.issuer.clearing;

import static io.github.eunini.issuer.ledger.LedgerService.Leg.credit;
import static io.github.eunini.issuer.ledger.LedgerService.Leg.debit;

import io.github.eunini.issuer.auth.AuthorizationService;
import io.github.eunini.issuer.clearing.ClearingFile.*;
import io.github.eunini.issuer.common.ApiException;
import io.github.eunini.issuer.common.PanRefs;
import io.github.eunini.issuer.disputes.DisputeService;
import io.github.eunini.issuer.ledger.LedgerService;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ingests clearing files: matches presentments to authorizations, posts to
 * the ledger, releases holds, and routes chargeback/representment records
 * to the dispute workflow. One file is one transaction.
 */
@Service
public class ClearingService {

    /** Restaurants, bars, fast food, taxis: tips may push the final amount above the authorization. */
    private static final Map<String, Integer> TOLERANCE_PERCENT = Map.of(
        "5812", 20, "5813", 20, "5814", 20, "4121", 20);
    private static final Set<String> MATCHABLE = Set.of("ACTIVE", "PARTIALLY_CLEARED", "EXPIRED");

    private final JdbcClient jdbc;
    private final LedgerService ledger;
    private final AuthorizationService auths;
    private final DisputeService disputes;
    private final PanRefs panRefs;
    private final Clock clock;

    public ClearingService(JdbcClient jdbc, LedgerService ledger, AuthorizationService auths, DisputeService disputes,
                           PanRefs panRefs, Clock clock) {
        this.jdbc = jdbc;
        this.ledger = ledger;
        this.auths = auths;
        this.disputes = disputes;
        this.panRefs = panRefs;
        this.clock = clock;
    }

    public record LineResult(String recordId, String type, String outcome, String authRef, Long disputeId,
                             long amountMinor) {}

    public record IngestReport(String fileId, int records, Map<String, Integer> outcomes, long postedMinor,
                               List<LineResult> lines) {}

    static int tolerancePercent(String mcc) {
        return mcc == null ? 0 : TOLERANCE_PERCENT.getOrDefault(mcc, 0);
    }

    @Transactional
    public IngestReport ingest(String text) {
        Parsed p = ClearingFile.parse(text);
        if (jdbc.sql("SELECT COUNT(*) FROM clearing_files WHERE file_id = ?").param(p.header().fileId())
            .query(Long.class).single() > 0) {
            throw ApiException.conflict("clearing file " + p.header().fileId() + " was already ingested");
        }
        var kh = new GeneratedKeyHolder();
        jdbc.sql("""
                INSERT INTO clearing_files (file_id, processing_date, sender, record_count, hash_total_minor,
                                            received_at)
                VALUES (?, ?, ?, ?, ?, ?)""")
            .params(p.header().fileId(), p.header().processingDate(), p.header().sender(), p.records().size(),
                p.hashTotalMinor(), OffsetDateTime.now(clock))
            .update(kh, "id");
        long fileRow = kh.getKey().longValue();

        List<LineResult> lines = new ArrayList<>();
        Map<String, Integer> outcomes = new LinkedHashMap<>();
        long posted = 0;
        for (ClearingRecord r : p.records()) {
            LineResult lr;
            if (jdbc.sql("SELECT COUNT(*) FROM clearing_records WHERE record_id = ?").param(r.recordId())
                .query(Long.class).single() > 0) {
                lr = new LineResult(r.recordId(), type(r), "DUPLICATE_RECORD", null, null, r.amountMinor());
            } else {
                lr = switch (r) {
                    case Presentment pr -> presentment(fileRow, pr);
                    case Chargeback cb -> {
                        var o = disputes.onChargebackSettled(cb.disputeRef(), cb.arn(), cb.amountMinor(),
                            p.header().processingDate());
                        insertRecord(fileRow, r, "CHBK", null, null, o.disputeId(), o.outcome(), o.entryId(),
                            cb.currency());
                        yield new LineResult(r.recordId(), "CHBK", o.outcome(), null, o.disputeId(), r.amountMinor());
                    }
                    case Representment rp -> {
                        var o = disputes.onRepresentment(rp.disputeRef(), rp.arn(), rp.amountMinor(),
                            p.header().processingDate(), rp.reason());
                        insertRecord(fileRow, r, "REPR", null, null, o.disputeId(), o.outcome(), o.entryId(),
                            rp.currency());
                        yield new LineResult(r.recordId(), "REPR", o.outcome(), null, o.disputeId(), r.amountMinor());
                    }
                };
                if (!lr.outcome().startsWith("UNMATCHED")) {
                    posted += r.amountMinor();
                }
            }
            outcomes.merge(lr.outcome(), 1, Integer::sum);
            lines.add(lr);
        }
        return new IngestReport(p.header().fileId(), p.records().size(), outcomes, posted, lines);
    }

    private static String type(ClearingRecord r) {
        return switch (r) {
            case Presentment x -> "PRES";
            case Chargeback x -> "CHBK";
            case Representment x -> "REPR";
        };
    }

    record Candidate(long id, String authRef, String rrn, long amount, long held, long cleared, String status,
                     OffsetDateTime createdAt) {}

    private LineResult presentment(long fileRow, Presentment p) {
        String panRef = panRefs.of(p.pan());
        Optional<long[]> card = jdbc.sql("""
                SELECT c.id, c.account_id, a.ledger_account_id
                  FROM cards c JOIN card_accounts a ON a.id = c.account_id WHERE c.pan_ref = ?""")
            .param(panRef)
            .query((rs, i) -> new long[] {rs.getLong(1), rs.getLong(2), rs.getLong(3)})
            .optional();
        long settlement = ledger.internal("NETWORK_SETTLEMENT", p.currency());
        if (card.isEmpty()) {
            // We still owe the network; park the debit in suspense for investigation.
            long entry = ledger.post("PRESENTMENT", "PRES:" + p.recordId(), "Unknown card " + p.arn(),
                List.of(debit(ledger.internal("CLEARING_SUSPENSE", p.currency()), p.amountMinor()),
                    credit(settlement, p.amountMinor()))).entryId();
            insertRecord(fileRow, p, "PRES", null, null, null, "UNKNOWN_CARD", entry, p.currency());
            return new LineResult(p.recordId(), "PRES", "UNKNOWN_CARD", null, null, p.amountMinor());
        }
        long cardId = card.get()[0];
        long accountId = card.get()[1];
        long cardholderLedger = card.get()[2];
        auths.lockAccount(accountId);

        Optional<Candidate> match = findMatch(cardId, p);
        long entry = ledger.post("PRESENTMENT", "PRES:" + p.recordId(),
            truncate(p.merchant(), 60) + " " + p.arn(),
            List.of(debit(cardholderLedger, p.amountMinor()), credit(settlement, p.amountMinor()))).entryId();

        String outcome;
        String authRef = null;
        Long authId = null;
        if (match.isPresent()) {
            Candidate a = match.get();
            authRef = a.authRef();
            authId = a.id();
            long remaining = Math.max(a.amount() - a.cleared(), 0);
            int tol = tolerancePercent(p.mcc());
            boolean over = p.amountMinor() * 100 > remaining * (100L + tol);
            boolean last = p.seq() == p.count();
            long release = last ? a.held() : Math.min(a.held(), p.amountMinor());
            jdbc.sql("""
                    UPDATE authorizations SET held_minor = ?, cleared_minor = cleared_minor + ?, status = ?
                     WHERE id = ?""")
                .params(a.held() - release, p.amountMinor(),
                    "EXPIRED".equals(a.status()) ? "EXPIRED" : last ? "CLEARED" : "PARTIALLY_CLEARED", a.id())
                .update();
            if (release > 0) {
                jdbc.sql("UPDATE card_accounts SET held_minor = held_minor - ? WHERE id = ?")
                    .params(release, accountId).update();
            }
            outcome = over ? "MATCHED_OVER_TOLERANCE" : "EXPIRED".equals(a.status()) ? "MATCHED_EXPIRED_HOLD"
                : "MATCHED";
        } else {
            outcome = "FORCE_POST";
        }
        insertRecord(fileRow, p, "PRES", cardId, authId, null, outcome, entry, p.currency());
        return new LineResult(p.recordId(), "PRES", outcome, authRef, null, p.amountMinor());
    }

    /**
     * Matching rules, strongest first:
     * 1. same card, same approval code and same RRN;
     * 2. same card and approval code, amount within tolerance of what is
     *    still uncleared, authorised within 30 days before the transaction date.
     */
    private Optional<Candidate> findMatch(long cardId, Presentment p) {
        List<Candidate> cands = jdbc.sql("""
                SELECT id, auth_ref, rrn, amount_minor, held_minor, cleared_minor, status, created_at
                  FROM authorizations
                 WHERE card_id = ? AND auth_code = ? AND status IN ('ACTIVE', 'PARTIALLY_CLEARED', 'EXPIRED')
                 ORDER BY id""")
            .params(cardId, p.authCode())
            .query((rs, i) -> new Candidate(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getLong(4),
                rs.getLong(5), rs.getLong(6), rs.getString(7), rs.getObject(8, OffsetDateTime.class)))
            .list();
        Optional<Candidate> exact = cands.stream()
            .filter(c -> MATCHABLE.contains(c.status()) && c.rrn() != null && c.rrn().equals(p.rrn()))
            .findFirst();
        if (exact.isPresent()) {
            return exact;
        }
        int tol = tolerancePercent(p.mcc());
        return cands.stream()
            .filter(c -> p.amountMinor() * 100 <= Math.max(c.amount() - c.cleared(), 0) * (100L + tol))
            .filter(c -> !c.createdAt().toLocalDate().isAfter(p.txnDate())
                && !c.createdAt().toLocalDate().isBefore(p.txnDate().minusDays(30)))
            .findFirst();
    }

    private void insertRecord(long fileRow, ClearingRecord r, String type, Long cardId, Long authId, Long disputeId,
                              String outcome, Long entryId, String currency) {
        Presentment p = r instanceof Presentment x ? x : null;
        jdbc.sql("""
                INSERT INTO clearing_records (file_id, record_id, record_type, arn, card_id, authorization_id,
                    dispute_id, auth_code, rrn, amount_minor, currency, mcc, merchant_name, txn_date,
                    presentment_seq, presentment_count, outcome, journal_entry_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""")
            .params(fileRow, r.recordId(), type, r.arn(), cardId, authId, disputeId,
                p == null ? null : p.authCode(), p == null ? null : p.rrn(), r.amountMinor(), currency,
                p == null ? null : p.mcc(), p == null ? null : truncate(p.merchant(), 64),
                p == null ? null : p.txnDate(), p == null ? null : p.seq(), p == null ? null : p.count(), outcome,
                entryId)
            .update();
    }

    private static String truncate(String s, int n) {
        return s == null || s.length() <= n ? s : s.substring(0, n);
    }
}
