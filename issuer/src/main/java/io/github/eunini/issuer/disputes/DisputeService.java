package io.github.eunini.issuer.disputes;

import static io.github.eunini.issuer.ledger.LedgerService.Leg.credit;
import static io.github.eunini.issuer.ledger.LedgerService.Leg.debit;

import io.github.eunini.issuer.common.ApiException;
import io.github.eunini.issuer.disputes.DisputeModels.*;
import io.github.eunini.issuer.ledger.LedgerService;
import io.github.eunini.issuer.ledger.LedgerService.Leg;
import java.time.Clock;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Chargeback workflow with deadlines, reason codes, evidence and a full
 * audit trail (every state change is a {@code dispute_events} row; every
 * money movement is a ledger entry referenced by dispute id).
 *
 * <p>Accounting (provisional credit is always given on opening):
 * <ul>
 *   <li>open: Dr DISPUTE_RECEIVABLE / Cr CARDHOLDER</li>
 *   <li>chargeback settled by network: Dr NETWORK_SETTLEMENT / Cr DISPUTE_RECEIVABLE</li>
 *   <li>representment: Dr DISPUTE_RECEIVABLE / Cr NETWORK_SETTLEMENT</li>
 *   <li>cardholder liable (lost, withdrawn): Dr CARDHOLDER / Cr DISPUTE_RECEIVABLE</li>
 *   <li>issuer absorbs (write-off, expired): Dr CHARGEBACK_LOSS / Cr DISPUTE_RECEIVABLE</li>
 *   <li>pre-arbitration won: Dr NETWORK_SETTLEMENT / Cr DISPUTE_RECEIVABLE</li>
 * </ul>
 */
@Service
public class DisputeService {

    private final JdbcClient jdbc;
    private final LedgerService ledger;
    private final Clock clock;

    public DisputeService(JdbcClient jdbc, LedgerService ledger, Clock clock) {
        this.jdbc = jdbc;
        this.ledger = ledger;
        this.clock = clock;
    }

    record Row(long id, String arn, long cardId, long accountId, String reasonCode, long amount, String currency,
               DisputeState state, LocalDate chargebackDeadline, LocalDate representmentDeadline,
               LocalDate prearbDeadline, long cardholderLedger) {}

    record Reason(String code, String description, int chargebackDays, int representmentDays, int prearbDays,
                  String requiredEvidence) {}

    public static String ref(long id) {
        return "DSP-" + id;
    }

    private Reason reason(String code) {
        return jdbc.sql("""
                SELECT code, description, chargeback_days, representment_days, prearb_days, required_evidence
                  FROM dispute_reason_codes WHERE code = ?""")
            .param(code)
            .query((rs, i) -> new Reason(rs.getString(1), rs.getString(2), rs.getInt(3), rs.getInt(4), rs.getInt(5),
                rs.getString(6)))
            .optional()
            .orElseThrow(() -> ApiException.rule("UNKNOWN_REASON_CODE", "unknown reason code " + code));
    }

    private Optional<Row> lock(long id) {
        return jdbc.sql("""
                SELECT d.id, d.arn, d.card_id, d.account_id, d.reason_code, d.amount_minor, d.currency, d.state,
                       d.chargeback_deadline, d.representment_deadline, d.prearb_deadline, a.ledger_account_id
                  FROM disputes d JOIN card_accounts a ON a.id = d.account_id
                 WHERE d.id = ? FOR UPDATE""")
            .param(id)
            .query((rs, i) -> new Row(rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getLong(4), rs.getString(5),
                rs.getLong(6), rs.getString(7), DisputeState.valueOf(rs.getString(8)),
                rs.getObject(9, LocalDate.class), rs.getObject(10, LocalDate.class), rs.getObject(11, LocalDate.class),
                rs.getLong(12)))
            .optional();
    }

    private Row mustLock(long id) {
        return lock(id).orElseThrow(() -> ApiException.notFound("dispute " + id));
    }

    private void transition(Row d, DisputeState to, String actor, String note) {
        if (!d.state().canMoveTo(to)) {
            throw ApiException.rule("INVALID_TRANSITION", "dispute " + d.id() + " cannot move from " + d.state()
                + " to " + to);
        }
        OffsetDateTime now = OffsetDateTime.now(clock);
        jdbc.sql("UPDATE disputes SET state = ?, closed_at = ? WHERE id = ?")
            .params(to.name(), to.isClosed() ? now : null, d.id()).update();
        event(d.id(), d.state().name(), to.name(), actor, note);
    }

    private void event(long id, String from, String to, String actor, String note) {
        jdbc.sql("""
                INSERT INTO dispute_events (dispute_id, from_state, to_state, actor, note, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""")
            .params(id, from, to, actor, note, OffsetDateTime.now(clock)).update();
    }

    private long post(Row d, String suffix, String description, Leg a, Leg b) {
        return ledger.post("DISPUTE", "DSP:" + d.id() + ":" + suffix, description, List.of(a, b)).entryId();
    }

    private long receivable(String ccy) {
        return ledger.internal("DISPUTE_RECEIVABLE", ccy);
    }

    @Transactional
    public DisputeView open(OpenDispute req) {
        var pres = jdbc.sql("""
                SELECT r.id, r.arn, r.card_id, c.account_id, r.amount_minor, r.currency, r.txn_date, r.record_type
                  FROM clearing_records r JOIN cards c ON c.id = r.card_id
                 WHERE r.record_id = ?""")
            .param(req.presentmentRecordId())
            .query((rs, i) -> new Object[] {rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getLong(4),
                rs.getLong(5), rs.getString(6), rs.getObject(7, LocalDate.class), rs.getString(8)})
            .optional()
            .orElseThrow(() -> ApiException.notFound("posted presentment " + req.presentmentRecordId()));
        if (!"PRES".equals(pres[7])) {
            throw ApiException.rule("NOT_A_PRESENTMENT", "disputes are opened against presentments");
        }
        long presId = (Long) pres[0];
        long presented = (Long) pres[4];
        if (req.amountMinor() > presented) {
            throw ApiException.rule("AMOUNT_EXCEEDS_PRESENTMENT", "dispute amount exceeds presented amount");
        }
        long open = jdbc.sql("""
                SELECT COUNT(*) FROM disputes WHERE presentment_id = ? AND state NOT LIKE 'CLOSED_%'""")
            .param(presId).query(Long.class).single();
        if (open > 0) {
            throw ApiException.conflict("an open dispute already exists for this presentment");
        }
        Reason reason = reason(req.reasonCode());
        LocalDate today = LocalDate.now(clock);
        LocalDate deadline = ((LocalDate) pres[6]).plusDays(reason.chargebackDays());
        if (today.isAfter(deadline)) {
            throw ApiException.rule("OUTSIDE_TIME_LIMIT", "chargeback time limit for " + reason.code()
                + " expired on " + deadline);
        }
        var kh = new GeneratedKeyHolder();
        jdbc.sql("""
                INSERT INTO disputes (presentment_id, arn, card_id, account_id, reason_code, amount_minor, currency,
                                      state, provisional_credit, opened_at, chargeback_deadline)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'OPENED', TRUE, ?, ?)""")
            .params(presId, pres[1], pres[2], pres[3], reason.code(), req.amountMinor(), pres[5],
                OffsetDateTime.now(clock), deadline)
            .update(kh, "id");
        long id = kh.getKey().longValue();
        event(id, null, DisputeState.OPENED.name(), "cardholder", req.note());
        Row d = mustLock(id);
        post(d, "PROVISIONAL", "Provisional credit " + ref(id),
            debit(receivable(d.currency()), d.amount()), credit(d.cardholderLedger(), d.amount()));
        return view(id);
    }

    @Transactional
    public DisputeView addEvidence(long id, Evidence e) {
        Row d = mustLock(id);
        if (d.state().isClosed()) {
            throw ApiException.rule("DISPUTE_CLOSED", "dispute is closed");
        }
        jdbc.sql("""
                INSERT INTO dispute_evidence (dispute_id, evidence_type, description, submitted_by, created_at)
                VALUES (?, ?, ?, ?, ?)""")
            .params(id, e.type(), e.description(), e.submittedBy(), OffsetDateTime.now(clock)).update();
        event(id, d.state().name(), d.state().name(), e.submittedBy(), "evidence added: " + e.type());
        return view(id);
    }

    @Transactional
    public DisputeView raiseChargeback(long id, String actor) {
        Row d = mustLock(id);
        Reason reason = reason(d.reasonCode());
        if (LocalDate.now(clock).isAfter(d.chargebackDeadline())) {
            throw ApiException.rule("OUTSIDE_TIME_LIMIT", "chargeback deadline " + d.chargebackDeadline()
                + " has passed");
        }
        long have = jdbc.sql("SELECT COUNT(*) FROM dispute_evidence WHERE dispute_id = ? AND evidence_type = ?")
            .params(id, reason.requiredEvidence()).query(Long.class).single();
        if (have == 0) {
            throw ApiException.rule("MISSING_EVIDENCE", "reason code " + reason.code() + " requires "
                + reason.requiredEvidence());
        }
        transition(d, DisputeState.CHARGEBACK_SENT, actor, "chargeback " + reason.code() + " sent to network");
        jdbc.sql("""
                INSERT INTO outgoing_chargebacks (dispute_id, arn, amount_minor, currency, reason_code, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""")
            .params(id, d.arn(), d.amount(), d.currency(), d.reasonCode(), OffsetDateTime.now(clock)).update();
        return view(id);
    }

    @Transactional
    public DisputeView resolve(long id, Resolution r) {
        Row d = mustLock(id);
        long amt = d.amount();
        String ccy = d.currency();
        switch (r.action()) {
            case WITHDRAW -> {
                transition(d, DisputeState.CLOSED_WITHDRAWN, r.actor(), r.note());
                post(d, "WITHDRAWN", "Provisional credit reversed " + ref(id),
                    debit(d.cardholderLedger(), amt), credit(receivable(ccy), amt));
            }
            case ACCEPT_REPRESENTMENT, PREARB_LOST -> {
                if (r.action() == Action.ACCEPT_REPRESENTMENT && d.state() != DisputeState.REPRESENTED) {
                    throw ApiException.rule("INVALID_TRANSITION", "no representment to accept");
                }
                transition(d, DisputeState.CLOSED_LOST, r.actor(), r.note());
                post(d, "REBILL", "Cardholder re-billed " + ref(id),
                    debit(d.cardholderLedger(), amt), credit(receivable(ccy), amt));
            }
            case WRITE_OFF -> {
                transition(d, DisputeState.CLOSED_WRITE_OFF, r.actor(), r.note());
                post(d, "WRITE_OFF", "Issuer absorbs " + ref(id),
                    debit(ledger.internal("CHARGEBACK_LOSS", ccy), amt), credit(receivable(ccy), amt));
            }
            case ESCALATE -> transition(d, DisputeState.PRE_ARBITRATION, r.actor(), r.note());
            case PREARB_WON -> {
                if (d.state() != DisputeState.PRE_ARBITRATION) {
                    throw ApiException.rule("INVALID_TRANSITION", "not in pre-arbitration");
                }
                transition(d, DisputeState.CLOSED_WON, r.actor(), r.note());
                post(d, "PREARB_WON", "Pre-arbitration won " + ref(id),
                    debit(ledger.internal("NETWORK_SETTLEMENT", ccy), amt), credit(receivable(ccy), amt));
            }
        }
        return view(id);
    }

    private Optional<Row> byRef(String disputeRef, String arn) {
        if (disputeRef == null || !disputeRef.startsWith("DSP-")) {
            return Optional.empty();
        }
        long id;
        try {
            id = Long.parseLong(disputeRef.substring(4));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
        return lock(id).filter(r -> r.arn().equals(arn));
    }

    /** CHBK record: the network confirms and settles the issuer's chargeback. */
    @Transactional
    public ClearingOutcome onChargebackSettled(String disputeRef, String arn, long amount, LocalDate processingDate) {
        Optional<Row> found = byRef(disputeRef, arn);
        if (found.isEmpty() || found.get().state() != DisputeState.CHARGEBACK_SENT || found.get().amount() != amount) {
            return new ClearingOutcome("UNMATCHED_CHARGEBACK", found.map(Row::id).orElse(null), null);
        }
        Row d = found.get();
        transition(d, DisputeState.CHARGEBACK_SETTLED, "network", "chargeback settled in clearing");
        LocalDate deadline = processingDate.plusDays(reason(d.reasonCode()).representmentDays());
        jdbc.sql("UPDATE disputes SET representment_deadline = ? WHERE id = ?").params(deadline, d.id()).update();
        long entry = post(d, "CB_SETTLED", "Chargeback settled " + ref(d.id()),
            debit(ledger.internal("NETWORK_SETTLEMENT", d.currency()), amount), credit(receivable(d.currency()),
                amount));
        return new ClearingOutcome("CHARGEBACK_SETTLED", d.id(), entry);
    }

    /** REPR record: the acquirer re-presents (second presentment). */
    @Transactional
    public ClearingOutcome onRepresentment(String disputeRef, String arn, long amount, LocalDate processingDate,
                                           String reasonText) {
        Optional<Row> found = byRef(disputeRef, arn);
        if (found.isEmpty() || found.get().state() != DisputeState.CHARGEBACK_SETTLED
            || found.get().amount() != amount) {
            return new ClearingOutcome("UNMATCHED_REPRESENTMENT", found.map(Row::id).orElse(null), null);
        }
        Row d = found.get();
        if (d.representmentDeadline() != null && processingDate.isAfter(d.representmentDeadline())) {
            return new ClearingOutcome("UNMATCHED_REPRESENTMENT_LATE", d.id(), null);
        }
        transition(d, DisputeState.REPRESENTED, "acquirer", "representment: " + reasonText);
        LocalDate deadline = processingDate.plusDays(reason(d.reasonCode()).prearbDays());
        jdbc.sql("UPDATE disputes SET prearb_deadline = ? WHERE id = ?").params(deadline, d.id()).update();
        long entry = post(d, "REPRESENTED", "Representment " + ref(d.id()),
            debit(receivable(d.currency()), amount),
            credit(ledger.internal("NETWORK_SETTLEMENT", d.currency()), amount));
        return new ClearingOutcome("REPRESENTED", d.id(), entry);
    }

    /** Apply deadline rules as of a date (run daily). */
    @Transactional
    public List<Transition> runDeadlines(LocalDate asOf) {
        List<Transition> out = new ArrayList<>();
        List<Long> ids = jdbc.sql("""
                SELECT id FROM disputes
                 WHERE (state = 'OPENED' AND chargeback_deadline < ?)
                    OR (state = 'CHARGEBACK_SETTLED' AND representment_deadline < ?)
                    OR (state = 'REPRESENTED' AND prearb_deadline < ?)
                 ORDER BY id""")
            .params(asOf, asOf, asOf).query(Long.class).list();
        for (long id : ids) {
            Row d = mustLock(id);
            long amt = d.amount();
            switch (d.state()) {
                case OPENED -> {
                    transition(d, DisputeState.CLOSED_EXPIRED, "system", "chargeback window missed");
                    post(d, "EXPIRED", "Chargeback window missed " + ref(id),
                        debit(ledger.internal("CHARGEBACK_LOSS", d.currency()), amt),
                        credit(receivable(d.currency()), amt));
                }
                case CHARGEBACK_SETTLED -> transition(d, DisputeState.CLOSED_WON, "system",
                    "no representment by " + d.representmentDeadline());
                case REPRESENTED -> {
                    transition(d, DisputeState.CLOSED_LOST, "system",
                        "no pre-arbitration by " + d.prearbDeadline() + "; representment accepted");
                    post(d, "REBILL", "Cardholder re-billed " + ref(id),
                        debit(d.cardholderLedger(), amt), credit(receivable(d.currency()), amt));
                }
                default -> {
                    continue;
                }
            }
            out.add(new Transition(id, d.state().name(), currentState(id)));
        }
        return out;
    }

    private String currentState(long id) {
        return jdbc.sql("SELECT state FROM disputes WHERE id = ?").param(id).query(String.class).single();
    }

    /** Outgoing chargeback records for the network (issuer -> network file). */
    public String outgoingFile(String fileId, LocalDate date) {
        List<String> lines = jdbc.sql("""
                SELECT dispute_id, arn, amount_minor, currency, reason_code FROM outgoing_chargebacks ORDER BY id""")
            .query((rs, i) -> "CHBK|OUT-" + rs.getLong(1) + "|" + rs.getString(2) + "|" + ref(rs.getLong(1)) + "|"
                + rs.getLong(3) + "|" + rs.getString(4) + "|" + rs.getString(5))
            .list();
        long total = jdbc.sql("SELECT COALESCE(SUM(amount_minor), 0) FROM outgoing_chargebacks")
            .query(Long.class).single();
        StringBuilder sb = new StringBuilder("HDR|CASCLR|1|" + fileId + "|"
            + date.toString().replace("-", "") + "|ISSUER\n");
        lines.forEach(l -> sb.append(l).append('\n'));
        sb.append("TRL|").append(lines.size()).append('|').append(total).append('\n');
        return sb.toString();
    }

    @Transactional(readOnly = true)
    public DisputeView view(long id) {
        var v = jdbc.sql("""
                SELECT d.id, d.arn, d.card_id, d.account_id, d.reason_code, r.description, d.amount_minor,
                       d.currency, d.state, d.chargeback_deadline, d.representment_deadline, d.prearb_deadline
                  FROM disputes d JOIN dispute_reason_codes r ON r.code = d.reason_code WHERE d.id = ?""")
            .param(id)
            .query((rs, i) -> new Object[] {rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getLong(4),
                rs.getString(5), rs.getString(6), rs.getLong(7), rs.getString(8), rs.getString(9),
                rs.getObject(10, LocalDate.class), rs.getObject(11, LocalDate.class),
                rs.getObject(12, LocalDate.class)})
            .optional()
            .orElseThrow(() -> ApiException.notFound("dispute " + id));
        List<EvidenceView> evidence = jdbc.sql("""
                SELECT evidence_type, description, submitted_by, created_at FROM dispute_evidence
                 WHERE dispute_id = ? ORDER BY id""")
            .param(id)
            .query((rs, i) -> new EvidenceView(rs.getString(1), rs.getString(2), rs.getString(3),
                rs.getObject(4, OffsetDateTime.class)))
            .list();
        List<EventView> events = jdbc.sql("""
                SELECT from_state, to_state, actor, note, created_at FROM dispute_events
                 WHERE dispute_id = ? ORDER BY id""")
            .param(id)
            .query((rs, i) -> new EventView(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getObject(5, OffsetDateTime.class)))
            .list();
        return new DisputeView((Long) v[0], ref((Long) v[0]), (String) v[1], (Long) v[2], (Long) v[3],
            (String) v[4], (String) v[5], (Long) v[6], (String) v[7], (String) v[8], (LocalDate) v[9],
            (LocalDate) v[10], (LocalDate) v[11], evidence, events);
    }
}
