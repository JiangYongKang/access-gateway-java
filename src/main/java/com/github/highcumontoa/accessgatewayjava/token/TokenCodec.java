package com.github.highcumontoa.accessgatewayjava.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.accessgatewayjava.config.GatewayProperties;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * 类 JWT 的令牌编解码与校验（HS256，进程内实现，无外部依赖）。
 *
 * <p>格式：base64url(header).base64url(payload).base64url(HMAC-SHA256)。
 * 校验顺序固定：格式 → kid 存在 → 签名 → 类型 → iss → aud → 密钥重叠期 → nbf → exp。
 * 时钟偏差容忍为闭区间：now ∈ [nbf - skew, exp + skew] 判定为有效，边界结论稳定可复现。
 */
@Service
public class TokenCodec {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";

    private static final String ALG = "HS256";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final GatewayProperties props;
    private final KeyService keyService;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();

    public TokenCodec(GatewayProperties props, KeyService keyService, Clock clock) {
        this.props = props;
        this.keyService = keyService;
        this.clock = clock;
    }

    /** 用当前在用密钥签发令牌。 */
    public String encode(TokenClaims claims) {
        String kid = keyService.activeKeyId();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", ALG);
        header.put("typ", "AGT");
        header.put("kid", kid);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", claims.getIssuer());
        payload.put("sub", claims.getSubject());
        payload.put("aud", claims.getAudience());
        payload.put("jti", claims.getTokenId());
        payload.put("typ", claims.getTokenType());
        payload.put("iat", claims.getIssuedAt().getEpochSecond());
        payload.put("nbf", claims.getNotBefore().getEpochSecond());
        payload.put("exp", claims.getExpiresAt().getEpochSecond());
        payload.put("roles", new ArrayList<>(claims.getRoles()));

        String headerPart = B64.encodeToString(toJson(header));
        String payloadPart = B64.encodeToString(toJson(payload));
        String signingInput = headerPart + "." + payloadPart;
        String signature = B64.encodeToString(hmac(keyService.activeKey(), signingInput));
        return signingInput + "." + signature;
    }

    /**
     * 校验并解析令牌。
     *
     * @param token            令牌串
     * @param expectedType     期望令牌类型（access/refresh）
     * @param expectedAudience 期望受众
     * @return 校验通过的令牌
     * @throws TokenException 校验失败，原因见 {@link TokenRejectReason}
     */
    public VerifiedToken verify(String token, String expectedType, String expectedAudience) {
        if (token == null || token.isBlank()) {
            throw new TokenException(TokenRejectReason.MALFORMED, "令牌为空");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new TokenException(TokenRejectReason.MALFORMED, "令牌必须是 header.payload.signature 三段结构");
        }

        JsonNode header = parseJson(decode(parts[0]), "头部");
        String alg = header.path("alg").asText(null);
        if (!ALG.equals(alg)) {
            throw new TokenException(TokenRejectReason.MALFORMED, "不支持的签名算法: " + alg);
        }
        String kid = header.path("kid").asText(null);
        if (kid == null) {
            throw new TokenException(TokenRejectReason.MALFORMED, "头部缺少 kid");
        }

        byte[] key = keyService.keyById(kid);
        if (key == null) {
            throw new TokenException(TokenRejectReason.UNKNOWN_SIGNING_KEY, "未知签名密钥 kid=" + kid);
        }

        byte[] expected = hmac(key, parts[0] + "." + parts[1]);
        byte[] actual;
        try {
            actual = B64D.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenRejectReason.MALFORMED, "签名段不是合法 Base64URL");
        }
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new TokenException(TokenRejectReason.SIGNATURE_MISMATCH, "签名校验失败，令牌可能被篡改");
        }

        JsonNode payload = parseJson(decode(parts[1]), "载荷");
        TokenClaims claims = toClaims(payload);

        if (!expectedType.equals(claims.getTokenType())) {
            throw new TokenException(TokenRejectReason.MALFORMED,
                    "令牌类型不符: 期望 " + expectedType + " 实际 " + claims.getTokenType());
        }
        if (!props.getIssuer().equals(claims.getIssuer())) {
            throw new TokenException(TokenRejectReason.ISSUER_MISMATCH,
                    "签发方不匹配: 期望 " + props.getIssuer() + " 实际 " + claims.getIssuer());
        }
        if (expectedAudience != null && !expectedAudience.equals(claims.getAudience())) {
            throw new TokenException(TokenRejectReason.AUDIENCE_MISMATCH,
                    "受众不匹配: 期望 " + expectedAudience + " 实际 " + claims.getAudience());
        }

        Instant now = clock.instant();
        KeyInfo keyInfo = keyService.infoById(kid);
        if (keyInfo != null && keyInfo.rejectAfter() != null && now.isAfter(keyInfo.rejectAfter())) {
            throw new TokenException(TokenRejectReason.KEY_OVERLAP_ENDED,
                    "签名密钥 " + kid + " 的重叠接受期已于 " + keyInfo.rejectAfter() + " 结束");
        }

        long skew = props.getToken().getClockSkewSeconds();
        if (now.isBefore(claims.getNotBefore().minusSeconds(skew))) {
            throw new TokenException(TokenRejectReason.NOT_YET_VALID,
                    "令牌尚未生效: nbf=" + claims.getNotBefore() + " 容忍=" + skew + "s 当前=" + now);
        }
        if (now.isAfter(claims.getExpiresAt().plusSeconds(skew))) {
            throw new TokenException(TokenRejectReason.EXPIRED,
                    "令牌已过期: exp=" + claims.getExpiresAt() + " 容忍=" + skew + "s 当前=" + now);
        }

        return new VerifiedToken(claims, kid);
    }

    private TokenClaims toClaims(JsonNode payload) {
        TokenClaims claims = new TokenClaims();
        claims.setIssuer(payload.path("iss").asText(null));
        claims.setSubject(payload.path("sub").asText(null));
        claims.setAudience(payload.path("aud").asText(null));
        claims.setTokenId(payload.path("jti").asText(null));
        claims.setTokenType(payload.path("typ").asText(null));
        claims.setIssuedAt(Instant.ofEpochSecond(payload.path("iat").asLong(0)));
        claims.setNotBefore(Instant.ofEpochSecond(payload.path("nbf").asLong(0)));
        claims.setExpiresAt(Instant.ofEpochSecond(payload.path("exp").asLong(0)));
        List<String> roles = new ArrayList<>();
        JsonNode rolesNode = payload.path("roles");
        if (rolesNode.isArray()) {
            rolesNode.forEach(node -> roles.add(node.asText()));
        }
        claims.setRoles(new LinkedHashSet<>(roles));
        return claims;
    }

    private byte[] toJson(Map<String, Object> map) {
        try {
            return mapper.writeValueAsBytes(map);
        } catch (Exception e) {
            throw new IllegalStateException("序列化令牌失败", e);
        }
    }

    private byte[] decode(String part) {
        try {
            return B64D.decode(part);
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenRejectReason.MALFORMED, "段不是合法 Base64URL");
        }
    }

    private JsonNode parseJson(byte[] bytes, String label) {
        try {
            return mapper.readTree(bytes);
        } catch (Exception e) {
            throw new TokenException(TokenRejectReason.MALFORMED, label + "不是合法 JSON");
        }
    }

    private byte[] hmac(byte[] key, String input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("签名计算失败", e);
        }
    }
}
