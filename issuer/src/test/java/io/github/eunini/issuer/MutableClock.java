package io.github.eunini.issuer;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** Test clock that can be moved forward to exercise expiry and deadlines. */
public class MutableClock extends Clock {

    public static final Instant START = Instant.parse("2026-10-02T12:00:00Z");
    private volatile Instant now = START;

    public void reset() {
        now = START;
    }

    public void advance(Duration d) {
        now = now.plus(d);
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return now;
    }
}
