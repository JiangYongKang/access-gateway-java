package com.github.highcumontoa.accessgatewayjava.policy;

import java.util.List;

/**
 * 一次访问判定结果与依据。
 *
 * @param allowed        是否允许
 * @param reason         人类可读的判定依据
 * @param matchedPolicyIds 命中的策略编号（无命中即默认拒绝）
 * @param policyVersion  判定时使用的策略版本
 */
public record Decision(boolean allowed, String reason, List<String> matchedPolicyIds, long policyVersion) {

    public static Decision allow(String reason, List<String> matched, long version) {
        return new Decision(true, reason, matched, version);
    }

    public static Decision deny(String reason, List<String> matched, long version) {
        return new Decision(false, reason, matched, version);
    }
}
