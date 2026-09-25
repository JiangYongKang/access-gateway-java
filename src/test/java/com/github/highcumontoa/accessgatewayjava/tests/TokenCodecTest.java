package com.github.highcumontoa.accessgatewayjava.tests;

import com.github.highcumontoa.accessgatewayjava.auth.IssuedTokens;
import com.github.highcumontoa.accessgatewayjava.token.TokenCodec;
import com.github.highcumontoa.accessgatewayjava.token.TokenException;
import com.github.highcumontoa.accessgatewayjava.token.TokenRejectReason;
import com.github.highcumontoa.accessgatewayjava.tests.support.TestGateway;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 令牌编解码与校验：篡改、签发方/受众不匹配等可区分原因。
 * 每个用例打印输入与判定依据（原因码 + 消息）。
 */
class TokenCodecTest {

    private static final Logger log = LoggerFactory.getLogger(TokenCodecTest.class);

    private TokenException verifyExpectReject(TestGateway gw, String token, String aud) {
        log.info("输入令牌(截断)={} 期望受众={}", abbreviate(token), aud);
        TokenException ex = assertThrows(TokenException.class,
                () -> gw.codec.verify(token, TokenCodec.TYPE_ACCESS, aud));
        log.info("判定依据: reason={} message={}", ex.getReason(), ex.getMessage());
        return ex;
    }

    @Test
    void validTokenRoundTrip() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        log.info("输入: 用户 alice 合法登录；输出访问令牌(截断)={}", abbreviate(tokens.accessToken()));

        var verified = gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api");
        log.info("判定依据: 校验通过 sub={} roles={} kid={}",
                verified.claims().getSubject(), verified.claims().getRoles(), verified.keyId());
        assertEquals("alice", verified.claims().getSubject());
        assertEquals(java.util.Set.of("reader"), verified.claims().getRoles());
    }

    @Test
    void malformedTokenRejected() {
        TestGateway gw = TestGateway.create();
        TokenException ex = verifyExpectReject(gw, "not-a-token", "demo-api");
        assertEquals(TokenRejectReason.MALFORMED, ex.getReason());
    }

    @Test
    void tamperedPayloadRejected() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        String[] parts = tokens.accessToken().split("\\.", -1);
        char replacement = parts[1].charAt(0) == 'A' ? 'B' : 'A';
        String tampered = parts[0] + "." + replacement + parts[1].substring(1) + "." + parts[2];

        TokenException ex = verifyExpectReject(gw, tampered, "demo-api");
        assertEquals(TokenRejectReason.SIGNATURE_MISMATCH, ex.getReason());
    }

    @Test
    void unknownSigningKeyRejected() {
        TestGateway gw = TestGateway.create();
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\",\"typ\":\"AGT\",\"kid\":\"key-999\"}".getBytes());
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"typ\":\"access\"}".getBytes());
        String forged = header + "." + payload + "." + "c2ln";

        TokenException ex = verifyExpectReject(gw, forged, "demo-api");
        assertEquals(TokenRejectReason.UNKNOWN_SIGNING_KEY, ex.getReason());
    }

    @Test
    void issuerMismatchRejected() {
        TestGateway signer = TestGateway.create(p -> p.setIssuer("issuer-a"));
        TestGateway verifier = TestGateway.create(p -> p.setIssuer("issuer-b"));
        IssuedTokens tokens = signer.auth.login("alice", "alice-pass", "demo-api");

        TokenException ex = verifyExpectReject(verifier, tokens.accessToken(), "demo-api");
        assertEquals(TokenRejectReason.ISSUER_MISMATCH, ex.getReason());
    }

    @Test
    void audienceMismatchRejected() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "api-a");

        TokenException ex = verifyExpectReject(gw, tokens.accessToken(), "api-b");
        assertEquals(TokenRejectReason.AUDIENCE_MISMATCH, ex.getReason());
    }

    @Test
    void wrongTypeRejected() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");

        TokenException ex = verifyExpectReject(gw, tokens.refreshToken(), "demo-api");
        assertEquals(TokenRejectReason.MALFORMED, ex.getReason());
    }

    private static String abbreviate(String token) {
        if (token == null) {
            return "null";
        }
        return token.length() <= 24 ? token : token.substring(0, 24) + "...";
    }
}
