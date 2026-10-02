package io.github.eunini.issuer.common;

import java.time.Clock;
import java.time.OffsetDateTime;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/** Append-only audit trail for administrative actions. */
@Component
public class Audit {

    private final JdbcClient jdbc;
    private final Clock clock;

    public Audit(JdbcClient jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    public void record(String entityType, long entityId, String action, String detail, String actor) {
        jdbc.sql("""
                INSERT INTO audit_events (entity_type, entity_id, action, detail, actor, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""")
            .params(entityType, entityId, action, detail, actor, OffsetDateTime.now(clock))
            .update();
    }
}
