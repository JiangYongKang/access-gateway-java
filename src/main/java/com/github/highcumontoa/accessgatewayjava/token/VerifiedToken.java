package com.github.highcumontoa.accessgatewayjava.token;

/**
 * 校验通过后的令牌：声明 + 实际签名密钥编号。
 */
public record VerifiedToken(TokenClaims claims, String keyId) {
}
