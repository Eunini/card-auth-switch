package io.github.eunini.issuer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.eunini.issuer.clearing.ClearingFile;
import io.github.eunini.issuer.common.ApiException;
import org.junit.jupiter.api.Test;

class ClearingFileTest {

    static final String ARN = "74100001626750000000017";

    static String file(String body, String trailer) {
        return "HDR|CASCLR|1|F1|20261002|ACQ1\n" + body + trailer;
    }

    @Test
    void parsesAllRecordTypes() {
        var p = ClearingFile.parse(file(
            "PRES|R1|" + ARN + "|9990010000001234|123456|627512000001|TERM0001|20261002|4250|840|5411|SHOP|1|1\n"
                + "CHBK|R2|" + ARN + "|DSP-1|4250|840|13.1\n"
                + "REPR|R3|" + ARN + "|DSP-1|4250|840|proof of delivery\n",
            "TRL|3|12750\n"));
        assertThat(p.header().fileId()).isEqualTo("F1");
        assertThat(p.records()).hasSize(3);
        assertThat(p.records().getFirst()).isInstanceOf(ClearingFile.Presentment.class);
        assertThat(p.hashTotalMinor()).isEqualTo(12750);
    }

    @Test
    void rejectsTrailerMismatchesAndBadFields() {
        String pres = "PRES|R1|" + ARN + "|9990010000001234|123456|627512000001|T1|20261002|4250|840|5411|S|1|1\n";
        assertThatThrownBy(() -> ClearingFile.parse(file(pres, "TRL|2|4250\n")))
            .isInstanceOf(ApiException.class).hasMessageContaining("count");
        assertThatThrownBy(() -> ClearingFile.parse(file(pres, "TRL|1|4251\n")))
            .hasMessageContaining("hash total");
        assertThatThrownBy(() -> ClearingFile.parse(file(pres.replace(ARN, "123"), "TRL|1|4250\n")))
            .hasMessageContaining("ARN");
        assertThatThrownBy(() -> ClearingFile.parse(file(pres.replace("|1|1\n", "|3|2\n"), "TRL|1|4250\n")))
            .hasMessageContaining("sequence");
        assertThatThrownBy(() -> ClearingFile.parse(file("XXXX|R9\n", "TRL|1|0\n")))
            .hasMessageContaining("line 2");
        assertThatThrownBy(() -> ClearingFile.parse("garbage")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> ClearingFile.parse(file(pres.replace("|4250|", "|-5|"), "TRL|1|-5\n")))
            .isInstanceOf(ApiException.class);
    }
}
