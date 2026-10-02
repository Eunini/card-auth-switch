package io.github.eunini.issuer.auth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Internal API contract with the switch (JSON field names are camelCase). */
public final class AuthModels {

    private AuthModels() {}

    public record AuthRequest(
        @NotBlank @Size(max = 80) String authRef,
        long cardId,
        long accountId,
        long amountMinor,
        @NotBlank String currency,
        @NotBlank String txnType,
        String mcc,
        String stan,
        String rrn,
        String terminalId,
        String merchantId,
        String merchantName,
        String entryMode,
        String transmittedAt,
        /** authRef of the original authorization when this is an incremental authorization. */
        String incrementalOf) {}

    public record AuthResponse(boolean approved, String responseCode, String authCode, Long availableMinor) {}

    public record AdviceRequest(
        @NotBlank @Size(max = 120) String adviceId,
        @NotBlank String source,
        @NotBlank String responseCode,
        String authCode,
        @NotNull @Valid AuthRequest auth) {}

    public record ReversalRequest(
        @NotBlank @Size(max = 120) String reversalRef,
        @NotBlank String authRef,
        Long replacementAmountMinor,
        String reason) {}

    public record StatusResponse(String status) {}
}
