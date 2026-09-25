package com.github.highcumontoa.accessgatewayjava.policy;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 策略判定引擎：默认拒绝，DENY 优先于 ALLOW。
 *
 * <p>判定顺序固定：
 * 1. 角色为空 → 默认拒绝；
 * 2. 任一角色命中 DENY → 拒绝；
 * 3. 任一角色命中 ALLOW → 允许；
 * 4. 否则 → 默认拒绝。
 * 判定依据（命中策略编号、策略版本、原因）随结果返回并写入审计。
 */
@Service
public class PolicyEngine {

    private final PolicyStore store;

    public PolicyEngine(PolicyStore store) {
        this.store = store;
    }

    /**
     * 判定一组角色是否可对资源执行动作。
     * 角色必须来自服务端签发的令牌，调用方不得传入客户端自报角色。
     */
    public Decision decide(Set<String> roles, String resource, String action) {
        long version = store.version();
        List<Policy> snapshot = store.snapshot();

        if (roles == null || roles.isEmpty()) {
            return Decision.deny("令牌不含任何角色，默认拒绝", List.of(), version);
        }

        List<String> denyHits = new ArrayList<>();
        List<String> allowHits = new ArrayList<>();
        for (Policy policy : snapshot) {
            for (String role : roles) {
                if (policy.matches(role, resource, action)) {
                    if (policy.effect() == Policy.Effect.DENY) {
                        denyHits.add(policy.id());
                    } else {
                        allowHits.add(policy.id());
                    }
                }
            }
        }

        if (!denyHits.isEmpty()) {
            return Decision.deny("命中 DENY 策略 " + denyHits + "，拒绝优先", denyHits, version);
        }
        if (!allowHits.isEmpty()) {
            return Decision.allow("命中 ALLOW 策略 " + allowHits, allowHits, version);
        }
        return Decision.deny("无匹配策略，默认拒绝", List.of(), version);
    }
}
