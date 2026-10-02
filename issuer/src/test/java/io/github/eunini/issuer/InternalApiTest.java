package io.github.eunini.issuer;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/** The JSON contract the Rust switch relies on (field names as serde emits them). */
@AutoConfigureMockMvc
class InternalApiTest extends IntegrationTest {

    @Autowired MockMvc mvc;

    @Test
    void authorizeReversalAndSnapshotContract() throws Exception {
        var c = issue(10_000);
        String body = """
            {"authRef":"TERM0001-1002-000123-627512000123","cardId":%d,"accountId":%d,"amountMinor":4250,
             "currency":"840","txnType":"PURCHASE","mcc":"5411","stan":"000123","rrn":"627512000123",
             "terminalId":"TERM0001","merchantId":"MERCH000000001","merchantName":"CORNER GROCERY",
             "entryMode":"051","transmittedAt":"1002143015"}""".formatted(c.cardId(), c.accountId());
        mvc.perform(post("/internal/v1/authorizations").contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.approved").value(true))
            .andExpect(jsonPath("$.responseCode").value("00"))
            .andExpect(jsonPath("$.availableMinor").value(5750));
        mvc.perform(post("/internal/v1/reversals").contentType(MediaType.APPLICATION_JSON).content("""
                {"reversalRef":"TERM0001-1002-000123-627512000123:FULL",
                 "authRef":"TERM0001-1002-000123-627512000123","replacementAmountMinor":null,"reason":"REQUEST"}"""))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("REVERSED"));
        mvc.perform(get("/internal/v1/cards/snapshot"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].cardId").exists())
            .andExpect(jsonPath("$[0].panRef").exists())
            .andExpect(jsonPath("$[0].dailyTxnCountLimit").exists());
        mvc.perform(post("/internal/v1/authorizations").contentType(MediaType.APPLICATION_JSON).content("{"))
            .andExpect(status().isBadRequest());
        mvc.perform(get("/internal/v1/health")).andExpect(jsonPath("$.status").value("UP"));
    }
}
