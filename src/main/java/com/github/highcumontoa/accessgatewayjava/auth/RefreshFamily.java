package com.github.highcumontoa.accessgatewayjava.auth;

import java.time.Instant;
import java.util.Set;

/**
 * 刷新令牌会话族：同一次登录签发的所有刷新令牌属于同一族。
 * 重用检测命中后整族吊销且不可恢复。
 */
public class RefreshFamily {

    private final String familyId;
    private final String subject;
    private final String audience;
    private final Set<String> roles;
    private final Instant createdAt;
    private volatile Instant expiresAt;
    private volatile boolean revoked;
    private volatile String revokeReason;
    private volatile String currentTokenId;

    public RefreshFamily(String familyId, String subject, String audience, Set<String> roles,
                         Instant createdAt, Instant expiresAt, String currentTokenId) {
        this.familyId = familyId;
        this.subject = subject;
        this.audience = audience;
        this.roles = roles;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.currentTokenId = currentTokenId;
    }

    public String getFamilyId() { return familyId; }
    public String getSubject() { return subject; }
    public String getAudience() { return audience; }
    public Set<String> getRoles() { return roles; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public boolean isRevoked() { return revoked; }
    public String getRevokeReason() { return revokeReason; }
    public void revoke(String reason) { this.revoked = true; this.revokeReason = reason; }
    public String getCurrentTokenId() { return currentTokenId; }
    public void setCurrentTokenId(String currentTokenId) { this.currentTokenId = currentTokenId; }
}
