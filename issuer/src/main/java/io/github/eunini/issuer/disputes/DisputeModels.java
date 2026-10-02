package io.github.eunini.issuer.disputes;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;

public final class DisputeModels {

    private DisputeModels() {}

    /** Open a dispute against a posted presentment (identified by its clearing record id). */
    public record OpenDispute(@NotBlank String presentmentRecordId, @NotBlank String reasonCode,
                              @Min(1) long amountMinor, @NotBlank String note) {}

    public record Evidence(@NotBlank String type, @NotBlank String description, @NotBlank String submittedBy) {}

    public enum Action { WITHDRAW, ACCEPT_REPRESENTMENT, WRITE_OFF, ESCALATE, PREARB_WON, PREARB_LOST }

    public record Resolution(Action action, @NotBlank String note, @NotBlank String actor) {}

    public record DeadlineRun(@Pattern(regexp = "\\d{4}-\\d{2}-\\d{2}") String asOf) {}

    public record EventView(String fromState, String toState, String actor, String note, OffsetDateTime at) {}

    public record EvidenceView(String type, String description, String submittedBy, OffsetDateTime at) {}

    public record DisputeView(long id, String disputeRef, String arn, long cardId, long accountId, String reasonCode,
                              String reasonDescription, long amountMinor, String currency, String state,
                              LocalDate chargebackDeadline, LocalDate representmentDeadline,
                              LocalDate prearbDeadline, List<EvidenceView> evidence, List<EventView> events) {}

    public record Transition(long disputeId, String from, String to) {}

    /** Result of a clearing record routed to the dispute workflow. */
    public record ClearingOutcome(String outcome, Long disputeId, Long entryId) {}
}
