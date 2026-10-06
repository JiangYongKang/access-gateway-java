package com.github.highcumontoa.gateway.audit;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 进程内审计日志：有界容量，达到上限按最旧优先淘汰；
 * 单调序号保证淘汰后剩余记录顺序稳定；写入与查询并发安全。
 */
@Component
public class AuditLog {
    private final int capacity;
    private final Clock clock;
    private final ArrayDeque<AuditEntry> entries = new ArrayDeque<>();
    private final ReentrantLock lock = new ReentrantLock();
    private long sequence = 0;

    public AuditLog() {
        this(10_000, Clock.systemUTC());
    }

    public AuditLog(int capacity, Clock clock) {
        this.capacity = capacity;
        this.clock = clock;
    }

    @Autowired
    public AuditLog(GatewayProperties properties, Clock clock) {
        this(properties.getAuditCapacity(), clock);
    }

    /** 追加一条审计记录，返回带序号的条目；超出容量时按最旧优先淘汰。 */
    public AuditEntry record(String eventType, String subject, String sessionId, List<String> roles,
                             String resource, String action, boolean allowed, String reason) {
        lock.lock();
        try {
            AuditEntry entry = new AuditEntry(++sequence, Instant.now(clock), eventType, subject,
                    sessionId, roles == null ? List.of() : List.copyOf(roles),
                    resource, action, allowed, reason);
            entries.addLast(entry);
            while (entries.size() > capacity) {
                entries.removeFirst();
            }
            return entry;
        } finally {
            lock.unlock();
        }
    }

    /** 全部现存条目（序号升序）。 */
    public List<AuditEntry> entries() {
        lock.lock();
        try {
            return new ArrayList<>(entries);
        } finally {
            lock.unlock();
        }
    }

    /**
     * 按条件筛选：subject/sessionId/allowed/eventType 精确匹配，
     * from/to 为闭区间（at >= from 且 at <= to）；空字段不限制。
     * 结果按序号升序，淘汰后剩余记录顺序仍然稳定。
     */
    public List<AuditEntry> query(AuditQuery query) {
        lock.lock();
        try {
            List<AuditEntry> result = new ArrayList<>();
            for (AuditEntry entry : entries) {
                if (matches(entry, query)) {
                    result.add(entry);
                }
            }
            return result;
        } finally {
            lock.unlock();
        }
    }

    private static boolean matches(AuditEntry entry, AuditQuery query) {
        if (query == null) {
            return true;
        }
        if (query.subject() != null && !query.subject().equals(entry.subject())) {
            return false;
        }
        if (query.sessionId() != null && !query.sessionId().equals(entry.sessionId())) {
            return false;
        }
        if (query.allowed() != null && query.allowed() != entry.allowed()) {
            return false;
        }
        if (query.eventType() != null && !query.eventType().equals(entry.eventType())) {
            return false;
        }
        if (query.from() != null && entry.at().isBefore(query.from())) {
            return false;
        }
        if (query.to() != null && entry.at().isAfter(query.to())) {
            return false;
        }
        return true;
    }

    /** 当前容量上限。 */
    public int capacity() {
        return capacity;
    }
}
