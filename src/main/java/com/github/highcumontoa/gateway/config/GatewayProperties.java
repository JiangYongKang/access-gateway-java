package com.github.highcumontoa.gateway.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** 网关可配置项：签发方、受众、令牌有效期、时钟偏差容忍、密钥重叠期等。 */
@ConfigurationProperties(prefix = "gateway")
public class GatewayProperties {
    private String issuer = "access-gateway";
    private String audience = "gateway-clients";
    private Duration accessTokenTtl = Duration.ofMinutes(15);
    private Duration refreshTokenTtl = Duration.ofHours(12);
    /** 客户端与服务端时钟偏差的确定容忍边界。 */
    private Duration clockSkewTolerance = Duration.ofSeconds(60);
    /** 密钥轮换后旧密钥继续用于验签的重叠期。 */
    private Duration keyOverlapPeriod = Duration.ofMinutes(30);
    /** 会话族从建立起的总可续期上限（无论怎样连续轮换，超过后一律不能再换出新令牌）。 */
    private Duration sessionMaxLifetime = Duration.ofDays(7);
    /** 会话族闲置超时：距上一次刷新活动超过该时长后不能再换出新令牌。 */
    private Duration sessionIdleTimeout = Duration.ofHours(8);
    /** 审计相关配置。 */
    private Audit audit = new Audit();

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    public Duration getAccessTokenTtl() { return accessTokenTtl; }
    public void setAccessTokenTtl(Duration accessTokenTtl) { this.accessTokenTtl = accessTokenTtl; }
    public Duration getRefreshTokenTtl() { return refreshTokenTtl; }
    public void setRefreshTokenTtl(Duration refreshTokenTtl) { this.refreshTokenTtl = refreshTokenTtl; }
    public Duration getClockSkewTolerance() { return clockSkewTolerance; }
    public void setClockSkewTolerance(Duration clockSkewTolerance) { this.clockSkewTolerance = clockSkewTolerance; }
    public Duration getKeyOverlapPeriod() { return keyOverlapPeriod; }
    public void setKeyOverlapPeriod(Duration keyOverlapPeriod) { this.keyOverlapPeriod = keyOverlapPeriod; }
    public Duration getSessionMaxLifetime() { return sessionMaxLifetime; }
    public void setSessionMaxLifetime(Duration sessionMaxLifetime) { this.sessionMaxLifetime = sessionMaxLifetime; }
    public Duration getSessionIdleTimeout() { return sessionIdleTimeout; }
    public void setSessionIdleTimeout(Duration sessionIdleTimeout) { this.sessionIdleTimeout = sessionIdleTimeout; }
    public Audit getAudit() { return audit; }
    public void setAudit(Audit audit) { this.audit = audit; }

    /** 审计日志配置。 */
    public static class Audit {
        /** 内存审计日志的容量上限，达到上限后按最旧优先淘汰。 */
        private int maxEntries = 1000;

        public int getMaxEntries() { return maxEntries; }
        public void setMaxEntries(int maxEntries) { this.maxEntries = maxEntries; }
    }
}
