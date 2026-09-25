package com.github.highcumontoa.accessgatewayjava.tests.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * 可控时钟：测试中显式推进或设置时间，保证时钟偏差/重叠期场景确定且可复现。
 */
public class TestClock extends Clock {

    private volatile Instant now;

    public TestClock(Instant start) {
        this.now = start;
    }

    public static TestClock startAt(Instant start) {
        return new TestClock(start);
    }

    public void advance(Duration duration) {
        this.now = now.plus(duration);
    }

    public void setInstant(Instant instant) {
        this.now = instant;
    }

    @Override
    public Instant instant() {
        return now;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }
}
