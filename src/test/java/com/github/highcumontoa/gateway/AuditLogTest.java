package com.github.highcumontoa.gateway;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import com.github.highcumontoa.gateway.audit.AuditEntry;
import com.github.highcumontoa.gateway.audit.AuditEventType;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.audit.AuditQuery;
import com.github.highcumontoa.gateway.support.MutableClock;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/** 审计：筛选查询、容量上限最旧优先淘汰且顺序稳定、高并发写入不丢不乱、可追溯。 */
class AuditLogTest {
    private static final Logger log = LoggerFactory.getLogger(AuditLogTest.class);
    private static final Instant T0 = Instant.parse("2026-10-07T00:00:00Z");

    @Test
    void filtersBySubjectSessionAllowedEventTypeAndTimeRange() {
        MutableClock clock = new MutableClock(T0);
        AuditLog auditLog = new AuditLog(1000, clock);
        auditLog.record(AuditEventType.SESSION_ESTABLISHED, "alice", "s1", List.of("reader"),
                "session", "establish", true, "会话建立");
        clock.advance(Duration.ofMinutes(1));
        auditLog.record(AuditEventType.ACCESS, "alice", "s1", List.of("reader"),
                "documents", "read", true, "命中策略 p1");
        clock.advance(Duration.ofMinutes(1));
        auditLog.record(AuditEventType.ACCESS, "alice", "s1", List.of("reader"),
                "documents", "write", false, "默认拒绝：无匹配策略");
        clock.advance(Duration.ofMinutes(1));
        auditLog.record(AuditEventType.ACCESS, "bob", "s2", List.of("writer"),
                "documents", "write", true, "命中策略 p2");

        List<AuditEntry> bySubject = auditLog.query(new AuditQuery("alice", null, null, null, null, null));
        List<AuditEntry> bySession = auditLog.query(new AuditQuery(null, "s2", null, null, null, null));
        List<AuditEntry> denied = auditLog.query(new AuditQuery(null, null, false, null, null, null));
        List<AuditEntry> byType = auditLog.query(
                new AuditQuery(null, null, null, AuditEventType.SESSION_ESTABLISHED, null, null));
        List<AuditEntry> byRange = auditLog.query(new AuditQuery(null, null, null, null,
                T0.plusSeconds(30), T0.plus(Duration.ofMinutes(2))));
        List<AuditEntry> combined = auditLog.query(new AuditQuery("alice", "s1", false, null, null, null));
        log.info("输入=4条混合审计, 判定依据=各筛选条件精确匹配, 结论=subject={} session={} denied={} type={} range={} combined={}",
                bySubject.size(), bySession.size(), denied.size(), byType.size(), byRange.size(), combined.size());
        assertEquals(3, bySubject.size());
        assertEquals(1, bySession.size());
        assertEquals("bob", bySession.get(0).subject());
        assertEquals(1, denied.size());
        assertEquals("默认拒绝：无匹配策略", denied.get(0).reason());
        assertEquals(1, byType.size());
        assertEquals(2, byRange.size(), "时间范围为闭区间");
        assertEquals(1, combined.size());
        assertEquals("write", combined.get(0).action());
    }

    @Test
    void capacityEvictsOldestFirstAndKeepsStableOrder() {
        MutableClock clock = new MutableClock(T0);
        AuditLog auditLog = new AuditLog(5, clock);
        for (int i = 1; i <= 8; i++) {
            clock.advance(Duration.ofSeconds(1));
            auditLog.record(AuditEventType.ACCESS, "user-" + i, "s-" + i, null,
                    "documents", "read", true, "第" + i + "条");
        }
        List<AuditEntry> entries = auditLog.entries();
        log.info("输入=容量5写入8条, 判定依据=最旧优先淘汰, 结论=剩余序号={}",
                entries.stream().map(AuditEntry::sequence).toList());
        assertEquals(5, entries.size());
        assertEquals(List.of(4L, 5L, 6L, 7L, 8L),
                entries.stream().map(AuditEntry::sequence).toList(), "淘汰后剩余记录按序号稳定升序");
        for (int i = 1; i < entries.size(); i++) {
            assertTrue(entries.get(i).sequence() > entries.get(i - 1).sequence());
            assertFalse(entries.get(i).at().isBefore(entries.get(i - 1).at()), "时间戳不倒挂");
        }
        // 淘汰后查询仍稳定且可追溯
        List<AuditEntry> survivor = auditLog.query(new AuditQuery("user-4", null, null, null, null, null));
        assertEquals(1, survivor.size());
        assertEquals("第4条", survivor.get(0).reason());
        assertTrue(auditLog.query(new AuditQuery("user-1", null, null, null, null, null)).isEmpty(),
                "已被淘汰的记录不再出现");
    }

    @Test
    void highConcurrentWritesLoseNothingAndStayOrdered() throws InterruptedException {
        MutableClock clock = new MutableClock(T0);
        int capacity = 500;
        AuditLog auditLog = new AuditLog(capacity, clock);
        int threads = 16;
        int perThread = 200;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        AtomicInteger queriesDone = new AtomicInteger();
        for (int t = 0; t < threads; t++) {
            int id = t;
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    for (int i = 0; i < perThread; i++) {
                        auditLog.record(AuditEventType.ACCESS, "user-" + id, "s-" + id, null,
                                "documents", "read", true, "并发写入");
                        if (i % 50 == 0) {
                            auditLog.query(AuditQuery.all()); // 写入同时并发查询不得报错
                            queriesDone.incrementAndGet();
                        }
                    }
                } catch (Throwable e) {
                    errors.add(e);
                }
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        List<AuditEntry> entries = auditLog.entries();
        log.info("输入={}线程x{}条并发写入(容量{}), 判定依据=无异常且序号严格递增, 结论=剩余{}条, 并发查询{}次, 异常={}",
                threads, perThread, capacity, entries.size(), queriesDone.get(), errors);
        assertTrue(errors.isEmpty(), "并发写入/查询不得报错: " + errors);
        assertEquals(capacity, entries.size(), "写入总量超过容量时恰好保留容量上限条数");
        long expectedFirst = (long) threads * perThread - capacity + 1;
        assertEquals(expectedFirst, entries.get(0).sequence(), "最旧的" + (expectedFirst - 1) + "条已被淘汰");
        for (int i = 1; i < entries.size(); i++) {
            assertEquals(entries.get(i - 1).sequence() + 1, entries.get(i).sequence(),
                    "序号必须连续递增、不丢不乱");
        }
        // 高并发后筛选查询仍一致
        assertEquals(entries.size(), auditLog.query(AuditQuery.all()).size());
    }

    @Test
    void entriesCarryEnoughContextForPostmortem() {
        MutableClock clock = new MutableClock(T0);
        AuditLog auditLog = new AuditLog(100, clock);
        auditLog.record(AuditEventType.REFRESH_REUSE_DETECTED, "alice", "fam-9", List.of("reader"),
                "session", "refresh", false, "刷新令牌重用检测，会话族已吊销");
        AuditEntry entry = auditLog.entries().get(0);
        log.info("输入=重用检测事件, 判定依据=条目字段完整, 结论={}", entry);
        assertEquals(T0, entry.at());
        assertEquals("alice", entry.subject());
        assertEquals("fam-9", entry.sessionId());
        assertEquals(AuditEventType.REFRESH_REUSE_DETECTED, entry.eventType());
        assertFalse(entry.allowed());
        assertFalse(entry.reason().isBlank(), "必须携带可解释的判定依据");
        assertTrue(entry.sequence() > 0);
    }
}
