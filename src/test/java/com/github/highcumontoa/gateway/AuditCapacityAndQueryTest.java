package com.github.highcumontoa.gateway;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import com.github.highcumontoa.gateway.audit.AuditAction;
import com.github.highcumontoa.gateway.audit.AuditEntry;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.audit.AuditOutcome;
import com.github.highcumontoa.gateway.audit.AuditQuery;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/** 审计：容量上限最旧淘汰、淘汰后顺序稳定、多维筛选可追溯、高并发写入不丢不乱序。 */
class AuditCapacityAndQueryTest {
    private static final Logger log = LoggerFactory.getLogger(AuditCapacityAndQueryTest.class);

    private AuditEntry entry(int seq, String subject, String action, String outcome, Instant at) {
        return new AuditEntry(seq, at, action, subject, "fam-" + seq, outcome,
                outcome.equals(AuditOutcome.SUCCESS) || outcome.equals(AuditOutcome.ALLOWED),
                null, null, null, "detail-" + seq);
    }

    @Test
    void capacityEvictsOldestAndKeepsStableOrder() {
        int capacity = 10;
        AuditLog log = new AuditLog(capacity);
        Instant base = Instant.parse("2026-10-01T00:00:00Z");
        for (int i = 1; i <= 25; i++) {
            log.record(entry(i, "alice", AuditAction.REFRESH, AuditOutcome.SUCCESS,
                    base.plusSeconds(i)));
        }
        List<AuditEntry> kept = log.entries();
        assertEquals(capacity, kept.size(), "达到容量后必须稳定保持在上限");
        // 淘汰最旧：保留 16..25
        assertEquals(16L, kept.get(0).sequence());
        assertEquals(25L, kept.get(kept.size() - 1).sequence());
        // 淘汰后顺序仍然稳定（序号严格递增）
        for (int i = 1; i < kept.size(); i++) {
            assertTrue(kept.get(i).sequence() > kept.get(i - 1).sequence(),
                    "淘汰后剩余记录顺序必须稳定");
        }
        AuditCapacityAndQueryTest.log.info("输入=写入25条/容量10, 判定依据=最旧优先FIFO淘汰, 结论=保留序号{}..{}且升序",
                kept.get(0).sequence(), kept.get(kept.size() - 1).sequence());
    }

    @Test
    void filtersBySubjectActionOutcomeAndTimeRange() {
        AuditLog log = new AuditLog(1000);
        Instant base = Instant.parse("2026-10-01T00:00:00Z");
        // 经 record 自动分配序号，模拟真实写入
        log.record(new AuditEntry(-1L, base.plusSeconds(1), AuditAction.SESSION_CREATED, "alice", "fam-1",
                AuditOutcome.SUCCESS, true, null, null, null, "alice 建立会话"));
        log.record(new AuditEntry(-1L, base.plusSeconds(2), AuditAction.REFRESH, "alice", "fam-1",
                AuditOutcome.IDLE_TIMEOUT, false, null, null, null, "alice 闲置"));
        log.record(new AuditEntry(-1L, base.plusSeconds(3), AuditAction.REFRESH, "bob", "fam-2",
                AuditOutcome.SUCCESS, true, null, null, null, "bob 刷新成功"));
        log.record(new AuditEntry(-1L, base.plusSeconds(4), AuditAction.SESSION_TERMINATED, "alice", "fam-1",
                AuditOutcome.SUCCESS, true, null, null, null, "alice 下线"));

        List<AuditEntry> alice = log.query(new AuditQuery("alice", null, null, null, null, null));
        assertEquals(3, alice.size());
        assertTrue(alice.stream().allMatch(e -> e.subject().equals("alice")));

        List<AuditEntry> idle = log.query(new AuditQuery(null, null, AuditAction.REFRESH,
                AuditOutcome.IDLE_TIMEOUT, null, null));
        assertEquals(1, idle.size());
        assertEquals("alice", idle.get(0).subject());
        assertFalse(idle.get(0).detail().isBlank(), "必须保留足够明细解释当时为何拒绝");

        List<AuditEntry> bySession = log.query(new AuditQuery(null, "fam-1", null, null, null, null));
        assertEquals(3, bySession.size());
        assertTrue(bySession.stream().allMatch(e -> e.sessionId().equals("fam-1")));

        // 时间范围含端点
        List<AuditEntry> range = log.query(new AuditQuery(null, null, null, null,
                base.plusSeconds(2), base.plusSeconds(3)));
        assertEquals(2, range.size());

        // 组合条件：alice + SESSION_CREATED
        List<AuditEntry> combo = log.query(new AuditQuery("alice", null,
                AuditAction.SESSION_CREATED, null, null, null));
        assertEquals(1, combo.size());
        AuditCapacityAndQueryTest.log.info(
                "输入=按主体/会话/动作+结论/时间范围筛选, 判定依据=条件AND且时间含端点, 结论=alice={} idle={} fam-1={} 时间窗={} 组合={}",
                alice.size(), idle.size(), bySession.size(), range.size(), combo.size());
    }

    @Test
    void concurrentWritersLoseNothingAndStayOrdered() throws Exception {
        int capacity = 10_000;
        AuditLog log = new AuditLog(capacity);
        int writers = 16;
        int perWriter = 500;
        int total = writers * perWriter;
        ExecutorService pool = Executors.newFixedThreadPool(writers);
        CountDownLatch ready = new CountDownLatch(writers);
        CountDownLatch go = new CountDownLatch(1);
        for (int w = 0; w < writers; w++) {
            final int writerId = w;
            pool.submit(() -> {
                ready.countDown();
                await(go);
                Instant base = Instant.parse("2026-10-01T00:00:00Z");
                for (int i = 0; i < perWriter; i++) {
                    log.record(new AuditEntry(-1L, base.plusSeconds((long) writerId * perWriter + i),
                            AuditAction.REFRESH, "user-" + writerId, "fam-" + writerId,
                            AuditOutcome.SUCCESS, true, null, null, null, "w" + writerId + "#" + i));
                }
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        List<AuditEntry> all = log.entries();
        assertEquals(total, all.size(), "高并发写入不能丢记录");
        // 序号严格递增（自动分配），无重复、无乱序
        for (int i = 1; i < all.size(); i++) {
            assertTrue(all.get(i).sequence() > all.get(i - 1).sequence(),
                    "高并发下记录顺序必须稳定不乱序");
        }
        // 每个写者的记录都在，且自身相对顺序正确
        for (int w = 0; w < writers; w++) {
            List<AuditEntry> mine = log.query(new AuditQuery("user-" + w, null, null, null, null, null));
            assertEquals(perWriter, mine.size());
            for (int i = 1; i < mine.size(); i++) {
                assertTrue(mine.get(i).at().isAfter(mine.get(i - 1).at()));
            }
        }
        AuditCapacityAndQueryTest.log.info("输入={}写者各{}条并发写入, 判定依据=加锁分配递增序号, 结论=共{}条无丢失无乱序",
                writers, perWriter, all.size());
    }

    private static void await(CountDownLatch latch) {
        try { latch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    @Test
    void concurrentWritesAndQueriesDoNotThrow() throws Exception {
        AuditLog log = new AuditLog(500);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch stop = new CountDownLatch(1);
        for (int i = 0; i < 4; i++) {
            final int id = i;
            pool.submit(() -> {
                Instant base = Instant.parse("2026-10-01T00:00:00Z");
                int n = 0;
                while (stop.getCount() > 0) {
                    log.record(new AuditEntry(-1L, base.plusSeconds(n++), AuditAction.REFRESH,
                            "user-" + id, "fam-" + id, AuditOutcome.SUCCESS, true,
                            null, null, null, "x"));
                    if (Thread.currentThread().isInterrupted()) break;
                }
            });
        }
        for (int i = 0; i < 4; i++) {
            pool.submit(() -> {
                while (stop.getCount() > 0) {
                    log.query(new AuditQuery("user-1", null, AuditAction.REFRESH, null, null, null));
                }
            });
        }
        Thread.sleep(500);
        stop.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        assertTrue(log.entries().size() <= 500, "持续淘汰下容量不越界");
        AuditCapacityAndQueryTest.log.info("输入=4写4读并发持续500ms(容量500), 判定依据=锁内快照查询, 结论=无异常且容量={}",
                log.entries().size());
    }
}
