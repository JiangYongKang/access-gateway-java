package com.github.highcumontoa.gateway.token;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import org.springframework.stereotype.Service;

/**
 * HMAC-SHA256 紧凑令牌（header.payload.signature）的签发与校验。
 * 时钟偏差判定规则（确定且可复现）：
 *   过期判定：now > exp + skewTolerance  => EXPIRED；now <= exp + skewTolerance 视为有效。
 *   未生效判定：now < iat - skewTolerance => NOT_YET_VALID。
 * 即偏差在容忍边界内（含边界）接受，超出边界拒绝。
 */
@Service
public class JwtService {
    private final GatewayProperties properties;
    private final KeyManager keyManager;
    private final Clock clock;

    public JwtService(GatewayProperties properties, KeyManager keyManager, Clock clock) {
        this.properties = properties;
        this.keyManager = keyManager;
        this.clock = clock;
    }

    public String issue(String subject, List<String> roles, String sessionFamily) {
        SigningKey key = keyManager.currentKey();
        Instant now = Instant.now(clock);
        Instant exp = now.plus(properties.getAccessTokenTtl());
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"" + key.keyId() + "\"}";
        String payload = "{\"sub\":\"" + escape(subject) + "\","
                + "\"iss\":\"" + escape(properties.getIssuer()) + "\","
                + "\"aud\":\"" + escape(properties.getAudience()) + "\","
                + "\"iat\":" + now.getEpochSecond() + ","
                + "\"exp\":" + exp.getEpochSecond() + ","
                + "\"fam\":\"" + escape(sessionFamily) + "\","
                + "\"roles\":" + toJsonArray(roles) + "}";
        String unsigned = b64(header.getBytes(StandardCharsets.UTF_8)) + "."
                + b64(payload.getBytes(StandardCharsets.UTF_8));
        return unsigned + "." + b64(hmac(unsigned, key.secret()));
    }

    public TokenValidationResult validate(String token) {
        if (token == null) {
            return TokenValidationResult.fail(TokenFailureReason.MALFORMED);
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            return TokenValidationResult.fail(TokenFailureReason.MALFORMED);
        }
        String headerJson;
        String payloadJson;
        byte[] signature;
        try {
            headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            signature = Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            return TokenValidationResult.fail(TokenFailureReason.MALFORMED);
        }
        String kid = extractString(headerJson, "kid");
        if (kid == null) {
            return TokenValidationResult.fail(TokenFailureReason.MALFORMED);
        }
        SigningKey key = keyManager.findForVerify(kid);
        if (key == null) {
            return TokenValidationResult.fail(keyManager.knownKeyId(kid)
                    ? TokenFailureReason.KEY_RETIRED : TokenFailureReason.UNKNOWN_KEY);
        }
        byte[] expected = hmac(parts[0] + "." + parts[1], key.secret());
        if (!constantTimeEquals(expected, signature)) {
            return TokenValidationResult.fail(TokenFailureReason.BAD_SIGNATURE);
        }
        String iss = extractString(payloadJson, "iss");
        String aud = extractString(payloadJson, "aud");
        String sub = extractString(payloadJson, "sub");
        String fam = extractString(payloadJson, "fam");
        Long iat = extractLong(payloadJson, "iat");
        Long exp = extractLong(payloadJson, "exp");
        if (iss == null || aud == null || sub == null || iat == null || exp == null) {
            return TokenValidationResult.fail(TokenFailureReason.MALFORMED);
        }
        if (!iss.equals(properties.getIssuer())) {
            return TokenValidationResult.fail(TokenFailureReason.ISSUER_MISMATCH);
        }
        if (!aud.equals(properties.getAudience())) {
            return TokenValidationResult.fail(TokenFailureReason.AUDIENCE_MISMATCH);
        }
        Instant now = Instant.now(clock);
        long skew = properties.getClockSkewTolerance().getSeconds();
        if (now.getEpochSecond() > exp + skew) {
            return TokenValidationResult.fail(TokenFailureReason.EXPIRED);
        }
        if (now.getEpochSecond() < iat - skew) {
            return TokenValidationResult.fail(TokenFailureReason.NOT_YET_VALID);
        }
        List<String> roles = extractStringArray(payloadJson, "roles");
        return TokenValidationResult.ok(new AccessTokenClaims(
                sub, roles, iss, aud, Instant.ofEpochSecond(iat), Instant.ofEpochSecond(exp), kid, fam));
    }

    // ---- 内部工具 ----

    private byte[] hmac(String data, byte[] secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static String b64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String toJsonArray(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(escape(items.get(i))).append('"');
        }
        return sb.append(']').toString();
    }

    /** 极简 JSON 字段提取（仅支持本服务签发的扁平结构）。 */
    static String extractString(String json, String field) {
        String needle = "\"" + field + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) return null;
        start += needle.length();
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) { sb.append(json.charAt(i + 1)); i++; }
            else if (c == '"') return sb.toString();
            else sb.append(c);
        }
        return null;
    }

    static Long extractLong(String json, String field) {
        String needle = "\"" + field + "\":";
        int start = json.indexOf(needle);
        if (start < 0) return null;
        start += needle.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        try {
            return Long.parseLong(json.substring(start, end));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static List<String> extractStringArray(String json, String field) {
        String needle = "\"" + field + "\":[";
        int start = json.indexOf(needle);
        if (start < 0) return List.of();
        start += needle.length();
        int end = json.indexOf(']', start);
        if (end < 0) return List.of();
        String body = json.substring(start, end);
        List<String> result = new ArrayList<>();
        int idx = 0;
        while (idx < body.length()) {
            int q1 = body.indexOf('"', idx);
            if (q1 < 0) break;
            int q2 = body.indexOf('"', q1 + 1);
            if (q2 < 0) break;
            result.add(body.substring(q1 + 1, q2));
            idx = q2 + 1;
        }
        return result;
    }
}
