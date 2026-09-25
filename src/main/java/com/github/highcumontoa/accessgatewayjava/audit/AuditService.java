package com.github.highcumontoa.accessgatewayjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 进程内审计日志：记录每次允许/拒绝及判定依据。
 * 追加写线程安全；同时输出到应用日志便于追溯。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();

    /** 追加一条审计事件。 */
    public void record(AuditEvent event) {
        events.add(event);
        log.info("AUDIT subject={} roles={} resource={} action={} allowed={} reason={} matched={} policyVersion={}",
                event.subject(), event.roles(), event.resource(), event.action(),
                event.allowed(), event.reason(), event.matchedPolicyIds(), event.policyVersion());
    }

    /** 全部审计事件（按记录顺序）。 */
    public List<AuditEvent> list() {
        return List.copyOf(events);
    }
}
