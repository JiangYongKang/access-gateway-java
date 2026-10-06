package com.github.highcumontoa.gateway.session;

import java.time.Instant;

/**
 * 会话视图：用于向用户展示自己的活跃会话。
 * 刻意不包含任何凭据（无访问/刷新令牌），只暴露元数据与状态。
 */
public record SessionInfo(
        String sessionId,
        String subject,
        Instant createdAt,
        Instant lastActivityAt,
        SessionState state) {}
