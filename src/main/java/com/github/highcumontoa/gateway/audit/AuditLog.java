package com.github.highcumontoa.gateway.audit;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 进程内审计日志：
 *  - 记录会话建立、刷新轮换、下线、重用检测、资源访问等安全事件及判定依据。
 *  - 容量可配（gateway.audit.max-entries），达到上限后按最旧优先淘汰（FIFO）。
 *  - 写入与淘汰在同一把锁内完成并分配单调递增序号，保证高并发下不丢记录、不乱序；
 *    查询在锁内复制快照，迭代期间不受并发写入影响。
 *  - 淘汰后剩余记录的相对顺序与序号顺序保持稳定。
 */
@Component
public class AuditLog {
    private final int capacity;
    private final Deque<AuditEntry> entries = new ArrayDeque<>();
    private final Object lock = new Object();
    private long sequenceGenerator = 0;

    /** 生产环境构造：按配置容量初始化。 */
    @Autowired
    public AuditLog(GatewayProperties properties) {
        this(properties.getAudit().getMaxEntries());
    }

    /** 无参构造：容量上限取默认值（便于单元测试）。 */
    public AuditLog() {
        this(new GatewayProperties().getAudit().getMaxEntries());
    }

    public AuditLog(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("audit capacity must be positive: " + capacity);
        }
        this.capacity = capacity;
    }

    /** 写入一条审计；若条目自带序号缺失（-1）则在此统一分配。超容量时淘汰最旧条目。 */
    public void record(AuditEntry entry) {
        synchronized (lock) {
            long seq = entry.sequence() >= 0 ? entry.sequence() : ++sequenceGenerator;
            AuditEntry stored = new AuditEntry(seq, entry.at(), entry.action(), entry.subject(),
                    entry.sessionId(), entry.outcome(), entry.success(), entry.roles(),
                    entry.resource(), entry.act(), entry.detail());
            entries.addLast(stored);
            while (entries.size() > capacity) {
                entries.pollFirst();
            }
        }
    }

    /** 全部审计条目，按写入（序号）升序的稳定快照。 */
    public List<AuditEntry> entries() {
        return query(AuditQuery.all());
    }

    /** 按条件筛选；各条件为 AND 关系，时间范围含端点；结果按序号升序。 */
    public List<AuditEntry> query(AuditQuery q) {
        synchronized (lock) {
            List<AuditEntry> result = new ArrayList<>(entries.size());
            for (AuditEntry e : entries) {
                if (matches(e, q)) {
                    result.add(e);
                }
            }
            return result;
        }
    }

    private static boolean matches(AuditEntry e, AuditQuery q) {
        if (q.subject() != null && !q.subject().equals(e.subject())) return false;
        if (q.sessionId() != null && !q.sessionId().equals(e.sessionId())) return false;
        if (q.action() != null && !q.action().equals(e.action())) return false;
        if (q.outcome() != null && !q.outcome().equals(e.outcome())) return false;
        Instant at = e.at();
        if (q.from() != null && at.isBefore(q.from())) return false;
        if (q.to() != null && at.isAfter(q.to())) return false;
        return true;
    }

    public int capacity() {
        return capacity;
    }
}
