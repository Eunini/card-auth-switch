package io.github.eunini.issuer;

import io.github.eunini.issuer.auth.AuthModels.AuthRequest;
import io.github.eunini.issuer.auth.AuthorizationService;
import io.github.eunini.issuer.cards.CardModels.CardImport;
import io.github.eunini.issuer.cards.CardModels.ImportResult;
import io.github.eunini.issuer.cards.CardService;
import io.github.eunini.issuer.common.PanRefs;
import io.github.eunini.issuer.ledger.LedgerService;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ActiveProfilesResolver;

/** Spring context on H2 (PostgreSQL mode) with a controllable clock. */
@SpringBootTest(properties = "issuer.hold-expiry-interval-ms=86400000")
@ActiveProfiles(resolver = IntegrationTest.Profiles.class)
@Import(IntegrationTest.ClockConfig.class)
public abstract class IntegrationTest {

    @TestConfiguration
    static class ClockConfig {
        @Bean
        @Primary
        MutableClock testClock() {
            return new MutableClock();
        }
    }

    /**
     * Tests run on H2 (PostgreSQL mode) by default. Set ISSUER_TEST_PROFILE=pg
     * plus ISSUER_DB_URL/USER/PASSWORD to run the same suite on PostgreSQL.
     */
    public static class Profiles implements ActiveProfilesResolver {
        @Override
        public String[] resolve(Class<?> testClass) {
            String p = System.getenv("ISSUER_TEST_PROFILE");
            return new String[] {p == null || p.isBlank() ? "h2" : p};
        }
    }

    // Random start so repeated runs against a persistent PostgreSQL do not collide.
    private static final AtomicLong SEQ = new AtomicLong(ThreadLocalRandom.current().nextLong(1_000_000_000L));

    @Autowired protected MutableClock clock;
    @Autowired protected CardService cards;
    @Autowired protected AuthorizationService auths;
    @Autowired protected LedgerService ledger;
    @Autowired protected JdbcClient jdbc;
    @Autowired protected PanRefs panRefs;

    @BeforeEach
    void resetClock() {
        clock.reset();
    }

    /** A fresh 16-digit test PAN (fictional 999 BIN, not Luhn-checked by the back office). */
    protected static String newPan() {
        return "999001" + String.format("%010d", SEQ.incrementAndGet());
    }

    protected ImportResult issue(String pan, long balance, long creditLimit, String status) {
        CardImport c = new CardImport(panRefs.of(pan), pan.substring(pan.length() - 4), "2912", status, "1234", 1,
            "201", "00", 18, "840", "Test Holder", creditLimit, balance, 1_000_000, 100_000, 50);
        return cards.importCards(List.of(c)).getFirst();
    }

    protected ImportResult issue(long balance) {
        return issue(newPan(), balance, 0, "ACTIVE");
    }

    protected static String ref() {
        return "T-" + UUID.randomUUID();
    }

    protected static AuthRequest auth(ImportResult c, String ref, long amount, String mcc) {
        return new AuthRequest(ref, c.cardId(), c.accountId(), amount, "840", "PURCHASE", mcc, "000001",
            "627512000001", "TERM0001", "MERCH1", "Test Merchant", "051", "1002120000", null);
    }

    protected static AuthRequest auth(ImportResult c, String ref, long amount) {
        return auth(c, ref, amount, "5411");
    }

    protected long available(long accountId) {
        return cards.account(accountId).availableMinor();
    }
}
