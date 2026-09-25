package com.github.highcumontoa.gateway.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Service;

/**
 * 策略引擎：
 *  - 默认拒绝：没有任何允许策略命中时一律拒绝。
 *  - 热更新：replacePolicies 原子替换，后续请求立即使用新策略，无需重启。
 *  - 判定可解释：返回命中的策略描述作为判定依据。
 */
@Service
public class PolicyEngine {
    private final CopyOnWriteArrayList<Policy> policies = new CopyOnWriteArrayList<>();

    public PolicyEngine() {
        // 初始内置策略：reader 可读、writer 可写、admin 可管理。
        replacePolicies(List.of(
                new Policy("reader", "documents", "read", true),
                new Policy("writer", "documents", "write", true),
                new Policy("admin", "admin", "manage", true)));
    }

    /** 判定顺序：逐条匹配允许策略；任一命中即允许，否则默认拒绝。 */
    public AccessDecision evaluate(List<String> roles, String resource, String action) {
        List<String> matched = new ArrayList<>();
        for (Policy policy : policies) {
            boolean roleMatch = policy.role().equals("*") || roles.contains(policy.role());
            boolean resourceMatch = policy.resource().equals("*") || policy.resource().equals(resource);
            boolean actionMatch = policy.action().equals("*") || policy.action().equals(action);
            if (roleMatch && resourceMatch && actionMatch && policy.allow()) {
                matched.add("role=" + policy.role() + " resource=" + policy.resource()
                        + " action=" + policy.action());
            }
        }
        if (!matched.isEmpty()) {
            return AccessDecision.allow("命中允许策略", matched);
        }
        return AccessDecision.deny("默认拒绝：角色 " + roles + " 对 " + resource + ":" + action
                + " 无任何允许策略命中");
    }

    /** 原子替换全部策略，立即对后续请求生效。 */
    public void replacePolicies(List<Policy> newPolicies) {
        policies.clear();
        policies.addAll(newPolicies);
    }

    public List<Policy> currentPolicies() {
        return List.copyOf(policies);
    }
}
