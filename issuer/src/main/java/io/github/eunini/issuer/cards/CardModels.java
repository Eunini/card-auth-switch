package io.github.eunini.issuer.cards;

import io.github.eunini.issuer.ledger.LedgerService.PostingView;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.time.OffsetDateTime;
import java.util.List;

/** DTOs for card management. Field names match the switch's JSON. */
public final class CardModels {

    private CardModels() {}

    /** One card as issued by the personalisation bureau (no PAN, no PIN). */
    public record CardImport(
        @NotBlank String panRef,
        @Pattern(regexp = "\\d{4}") String last4,
        @Pattern(regexp = "\\d{4}") String expiry,
        @NotBlank String status,
        @Pattern(regexp = "\\d{4}") String pvv,
        @Min(0) int pvki,
        @Pattern(regexp = "\\d{3}") String serviceCode,
        @Pattern(regexp = "\\d{2}") String psn,
        int cvn,
        @Pattern(regexp = "\\d{3}") String currency,
        @NotBlank String holderName,
        @Min(0) long creditLimitMinor,
        @Min(0) long openingBalanceMinor,
        @Min(0) long perTxnLimitMinor,
        @Min(0) long dailyCashLimitMinor,
        @Min(0) int dailyTxnCountLimit) {}

    public record ImportResult(String panRef, long cardId, long accountId, boolean created) {}

    /** What the switch caches for each card (stand-in needs all of it). */
    public record CardProfile(long cardId, long accountId, String panRef, String last4, String expiry, String status,
                              String pvv, int pvki, String serviceCode, String psn, int cvn, String currency,
                              long perTxnLimitMinor, long dailyCashLimitMinor, int dailyTxnCountLimit) {}

    public record HoldView(String authRef, long amountMinor, long heldMinor, long clearedMinor, String status,
                           String source, String merchantName, String authCode, boolean overdraft,
                           OffsetDateTime expiresAt) {}

    public record AccountView(long accountId, String holderName, String currency, long ledgerBalanceMinor,
                              long heldMinor, long creditLimitMinor, long availableMinor, List<HoldView> holds,
                              List<PostingView> recentPostings) {}

    public record Deposit(@Min(1) long amountMinor, @NotBlank String reference) {}

    public record StatusChange(@Pattern(regexp = "ACTIVE|BLOCKED|LOST|STOLEN|CLOSED") String status,
                               @NotBlank String reason) {}
}
