package io.github.eunini.issuer.clearing;

import io.github.eunini.issuer.common.ApiException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Parser for the clearing file format (docs/clearing-format.md).
 *
 * <pre>
 * HDR|CASCLR|1|fileId|YYYYMMDD|sender
 * PRES|recordId|arn|pan|authCode|rrn|terminalId|txnDate|amountMinor|currency|mcc|merchant|seq|count
 * CHBK|recordId|arn|disputeRef|amountMinor|currency|reasonCode
 * REPR|recordId|arn|disputeRef|amountMinor|currency|reason
 * TRL|recordCount|hashTotalMinor
 * </pre>
 *
 * Validation is all-or-nothing: any structural error rejects the whole file
 * with the line number, before anything is posted.
 */
public final class ClearingFile {

    private static final DateTimeFormatter YMD = DateTimeFormatter.BASIC_ISO_DATE;
    private static final Pattern DIGITS = Pattern.compile("\\d+");
    private static final Pattern ARN = Pattern.compile("\\d{23}");

    public record Header(String fileId, LocalDate processingDate, String sender) {}

    public sealed interface ClearingRecord permits Presentment, Chargeback, Representment {
        String recordId();

        String arn();

        long amountMinor();

        int line();
    }

    public record Presentment(int line, String recordId, String arn, String pan, String authCode, String rrn,
                              String terminalId, LocalDate txnDate, long amountMinor, String currency, String mcc,
                              String merchant, int seq, int count) implements ClearingRecord {}

    public record Chargeback(int line, String recordId, String arn, String disputeRef, long amountMinor,
                             String currency, String reasonCode) implements ClearingRecord {}

    public record Representment(int line, String recordId, String arn, String disputeRef, long amountMinor,
                                String currency, String reason) implements ClearingRecord {}

    public record Parsed(Header header, List<ClearingRecord> records, long hashTotalMinor) {}

    private ClearingFile() {}

    private static ApiException err(int line, String msg) {
        return ApiException.badRequest("clearing file line " + line + ": " + msg);
    }

    private static long amount(int line, String s) {
        if (!DIGITS.matcher(s).matches() || s.length() > 15) {
            throw err(line, "invalid amount '" + s + "'");
        }
        long v = Long.parseLong(s);
        if (v <= 0) {
            throw err(line, "amount must be positive");
        }
        return v;
    }

    private static LocalDate date(int line, String s) {
        try {
            return LocalDate.parse(s, YMD);
        } catch (DateTimeParseException e) {
            throw err(line, "invalid date '" + s + "'");
        }
    }

    private static String arn(int line, String s) {
        if (!ARN.matcher(s).matches()) {
            throw err(line, "ARN must be 23 digits");
        }
        return s;
    }

    private static String currency(int line, String s) {
        if (!s.matches("\\d{3}")) {
            throw err(line, "currency must be ISO 4217 numeric");
        }
        return s;
    }

    private static void fields(int line, String[] f, int n) {
        if (f.length != n) {
            throw err(line, f[0] + " record needs " + n + " fields, got " + f.length);
        }
    }

    public static Parsed parse(String text) {
        String[] lines = text.strip().split("\\r?\\n");
        if (lines.length < 2) {
            throw err(1, "file needs at least a header and a trailer");
        }
        String[] h = lines[0].split("\\|", -1);
        if (h.length != 6 || !"HDR".equals(h[0]) || !"CASCLR".equals(h[1]) || !"1".equals(h[2])) {
            throw err(1, "expected HDR|CASCLR|1|fileId|date|sender");
        }
        if (h[3].isBlank() || h[3].length() > 64) {
            throw err(1, "invalid file id");
        }
        Header header = new Header(h[3], date(1, h[4]), h[5]);

        List<ClearingRecord> records = new ArrayList<>();
        for (int i = 1; i < lines.length - 1; i++) {
            int ln = i + 1;
            String[] f = lines[i].split("\\|", -1);
            switch (f[0]) {
                case "PRES" -> {
                    fields(ln, f, 14);
                    int seq = (int) amount(ln, f[12]);
                    int count = (int) amount(ln, f[13]);
                    if (seq > count) {
                        throw err(ln, "presentment sequence " + seq + " > count " + count);
                    }
                    if (!f[3].matches("\\d{12,19}")) {
                        throw err(ln, "invalid PAN");
                    }
                    records.add(new Presentment(ln, f[1], arn(ln, f[2]), f[3], f[4], f[5], f[6], date(ln, f[7]),
                        amount(ln, f[8]), currency(ln, f[9]), f[10], f[11], seq, count));
                }
                case "CHBK" -> {
                    fields(ln, f, 7);
                    records.add(new Chargeback(ln, f[1], arn(ln, f[2]), f[3], amount(ln, f[4]), currency(ln, f[5]),
                        f[6]));
                }
                case "REPR" -> {
                    fields(ln, f, 7);
                    records.add(new Representment(ln, f[1], arn(ln, f[2]), f[3], amount(ln, f[4]),
                        currency(ln, f[5]), f[6]));
                }
                default -> throw err(ln, "unknown record type '" + f[0] + "'");
            }
            if (records.getLast().recordId().isBlank()) {
                throw err(ln, "missing record id");
            }
        }
        int tl = lines.length;
        String[] t = lines[tl - 1].split("\\|", -1);
        if (t.length != 3 || !"TRL".equals(t[0]) || !DIGITS.matcher(t[1]).matches()
            || !DIGITS.matcher(t[2]).matches()) {
            throw err(tl, "expected TRL|recordCount|hashTotal");
        }
        long sum = records.stream().mapToLong(ClearingRecord::amountMinor).sum();
        if (Integer.parseInt(t[1]) != records.size()) {
            throw err(tl, "trailer count " + t[1] + " != " + records.size() + " records");
        }
        if (Long.parseLong(t[2]) != sum) {
            throw err(tl, "trailer hash total " + t[2] + " != " + sum);
        }
        return new Parsed(header, records, sum);
    }
}
