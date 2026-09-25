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
}
