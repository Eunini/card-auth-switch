package io.github.eunini.issuer.common;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * PAN references: HMAC-SHA256(key, PAN), first 16 bytes, lowercase hex. The
 * switch computes the same value, so cards are matched without the back
 * office ever storing a PAN. Clearing files carry PANs; they are converted
 * on ingest and not persisted.
 */
@Component
public class PanRefs {

    private final byte[] key;

    public PanRefs(@Value("${issuer.pan-hmac-key}") String keyHex) {
        this.key = HexFormat.of().parseHex(keyHex);
    }

    public String of(String pan) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] h = mac.doFinal(pan.getBytes(StandardCharsets.US_ASCII));
            return HexFormat.of().formatHex(h, 0, 16);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
