package com.github.highcumontoa.accessgatewayjava.token;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 访问令牌声明集合（类型定义，逻辑在后续迭代中填充）。
 * 角色只能由服务端在签发时写入，任何客户端声明均不参与鉴权。
 */
public class TokenClaims {

    private String issuer;
    private String subject;
    private String audience;
    private String tokenId;
    private String tokenType;
    private Instant issuedAt;
    private Instant notBefore;
    private Instant expiresAt;
    private Set<String> roles = new LinkedHashSet<>();

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    public String getTokenId() { return tokenId; }
    public void setTokenId(String tokenId) { this.tokenId = tokenId; }
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    public Instant getIssuedAt() { return issuedAt; }
    public void setIssuedAt(Instant issuedAt) { this.issuedAt = issuedAt; }
    public Instant getNotBefore() { return notBefore; }
    public void setNotBefore(Instant notBefore) { this.notBefore = notBefore; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }
}
