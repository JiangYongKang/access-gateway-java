package com.github.highcumontoa.gateway.audit;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Component;

/** 进程内审计日志：记录每次允许/拒绝及判定依据。 */
@Component
public class AuditLog {
    private final CopyOnWriteArrayList<AuditEntry> entries = new CopyOnWriteArrayList<>();

    public void record(AuditEntry entry) {
        entries.add(entry);
    }

    public List<AuditEntry> entries() {
        return List.copyOf(entries);
    }
}
