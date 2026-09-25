package com.github.highcumontoa.accessgatewayjava.policy;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 进程内策略库：默认拒绝语义下的规则集合，支持运行时热更新。
 *
 * <p>判定每次实时读取当前快照，replaceAll 之后的新请求立即使用新版本，
 * 无需重启。版本号随每次替换递增，写入审计与判定依据。
 */
@Service
public class PolicyStore {

    private final AtomicReference<List<Policy>> policies;
    private final AtomicLong version = new AtomicLong(1);

    public PolicyStore() {
        this.policies = new AtomicReference<>(List.of(
                new Policy("p-allow-reader-read-docs", "reader", "/docs", "read", Policy.Effect.ALLOW),
                new Policy("p-allow-writer-write-docs", "writer", "/docs", "write", Policy.Effect.ALLOW),
                new Policy("p-deny-writer-delete-docs", "writer", "/docs", "delete", Policy.Effect.DENY)
        ));
    }

    /** 当前策略快照（每次判定实时读取，保证变更立即生效）。 */
    public List<Policy> snapshot() {
        return policies.get();
    }

    /** 整体替换策略集，返回新版本号。 */
    public long replaceAll(List<Policy> policies) {
        if (policies == null) {
            throw new IllegalArgumentException("策略集不能为 null");
        }
        this.policies.set(List.copyOf(policies));
        return version.incrementAndGet();
    }

    /** 当前策略版本号（随每次变更递增，用于审计与判定依据）。 */
    public long version() {
        return version.get();
    }
}
