package io.github.eunini.issuer.disputes;

import java.util.EnumSet;
import java.util.Set;

/**
 * Dispute lifecycle (issuer side).
 *
 * <pre>
 * OPENED --chargeback--> CHARGEBACK_SENT --network confirms (CHBK)--> CHARGEBACK_SETTLED
 *   |                                                                   |            |
 *   +--> CLOSED_WITHDRAWN (cardholder withdraws)        no representment     acquirer re-presents (REPR)
 *   +--> CLOSED_EXPIRED (chargeback window missed)      by deadline              |
 *                                                          v                     v
 *                                                      CLOSED_WON           REPRESENTED --> CLOSED_LOST / CLOSED_WRITE_OFF
 *                                                                               |
 *                                                                               v
 *                                                                        PRE_ARBITRATION --> CLOSED_WON / CLOSED_LOST / CLOSED_WRITE_OFF
 * </pre>
 */
public enum DisputeState {
    OPENED,
    CHARGEBACK_SENT,
    CHARGEBACK_SETTLED,
    REPRESENTED,
    PRE_ARBITRATION,
    CLOSED_WON,
    CLOSED_LOST,
    CLOSED_WRITE_OFF,
    CLOSED_WITHDRAWN,
    CLOSED_EXPIRED;

    public Set<DisputeState> next() {
        return switch (this) {
            case OPENED -> EnumSet.of(CHARGEBACK_SENT, CLOSED_WITHDRAWN, CLOSED_EXPIRED);
            case CHARGEBACK_SENT -> EnumSet.of(CHARGEBACK_SETTLED);
            case CHARGEBACK_SETTLED -> EnumSet.of(REPRESENTED, CLOSED_WON);
            case REPRESENTED -> EnumSet.of(PRE_ARBITRATION, CLOSED_LOST, CLOSED_WRITE_OFF);
            case PRE_ARBITRATION -> EnumSet.of(CLOSED_WON, CLOSED_LOST, CLOSED_WRITE_OFF);
            default -> EnumSet.noneOf(DisputeState.class);
        };
    }

    public boolean canMoveTo(DisputeState to) {
        return next().contains(to);
    }

    public boolean isClosed() {
        return name().startsWith("CLOSED_");
    }
}
