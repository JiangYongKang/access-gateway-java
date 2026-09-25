package com.github.highcumontoa.accessgatewayjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 网关全部可配置项（前缀 gateway）。骨架阶段仅定义类型与默认值。
 */
@Component
@ConfigurationProperties(prefix = "gateway")
public class GatewayProperties {

    /** 令牌签发方标识（iss）。 */
    private String issuer = "local-access-gateway";

    /** 默认受众（aud），登录未显式指定时使用。 */
    private String defaultAudience = "demo-api";

    private final Token token = new Token();
    private final Key key = new Key();

    public static class Token {
        /** 访问令牌有效期（秒）。 */
        private long accessTtlSeconds = 300;
        /** 刷新令牌有效期（秒）。 */
        private long refreshTtlSeconds = 3600;
        /** 客户端与服务端时钟偏差容忍（秒），边界含容忍值。 */
        private long clockSkewSeconds = 30;

        public long getAccessTtlSeconds() { return accessTtlSeconds; }
        public void setAccessTtlSeconds(long accessTtlSeconds) { this.accessTtlSeconds = accessTtlSeconds; }
        public long getRefreshTtlSeconds() { return refreshTtlSeconds; }
        public void setRefreshTtlSeconds(long refreshTtlSeconds) { this.refreshTtlSeconds = refreshTtlSeconds; }
        public long getClockSkewSeconds() { return clockSkewSeconds; }
        public void setClockSkewSeconds(long clockSkewSeconds) { this.clockSkewSeconds = clockSkewSeconds; }
    }

    public static class Key {
        /** 旧密钥轮换后的重叠接受期（秒），超过后旧密钥签署的令牌一律拒绝。 */
        private long overlapSeconds = 600;
        /** 本地模拟用主密钥种子，仅用于派生进程内 HMAC 密钥，非真实凭据。 */
        private String seed = "local-demo-master-secret-do-not-use-in-prod";

        public long getOverlapSeconds() { return overlapSeconds; }
        public void setOverlapSeconds(long overlapSeconds) { this.overlapSeconds = overlapSeconds; }
        public String getSeed() { return seed; }
        public void setSeed(String seed) { this.seed = seed; }
    }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getDefaultAudience() { return defaultAudience; }
    public void setDefaultAudience(String defaultAudience) { this.defaultAudience = defaultAudience; }
    public Token getToken() { return token; }
    public Key getKey() { return key; }
}
