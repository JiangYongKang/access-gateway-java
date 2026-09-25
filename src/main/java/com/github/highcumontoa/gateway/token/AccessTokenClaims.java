package com.github.highcumontoa.gateway.token;

import java.time.Instant;
import java.util.List;

/** 校验通过后的访问令牌声明。角色只能来自服务端用户档案，不接受客户端注入。 */
public record AccessTokenClaims(
        String subject,
        List<String> roles,
        String issuer,
        String audience,
        Instant issuedAt,
        Instant expiresAt,
        String keyId,
        String sessionFamily) {}
