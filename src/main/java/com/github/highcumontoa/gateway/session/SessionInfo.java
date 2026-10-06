package com.github.highcumontoa.gateway.session;

import java.time.Instant;

/**
 * 会话视图：只暴露建立时间、最近活动时间与状态，不包含任何凭据。
 * sessionId 即刷新令牌会话族标识（fam）。
 */
public record SessionInfo(
        String sessionId,
        String username,
        Instant createdAt,
        Instant lastActivityAt,
        Status status) {

    public enum Status { ACTIVE, REVOKED }
}
