package com.github.highcumontoa.accessgatewayjava.tests;

import com.github.highcumontoa.accessgatewayjava.auth.IssuedTokens;
import com.github.highcumontoa.accessgatewayjava.token.TokenCodec;
import com.github.highcumontoa.accessgatewayjava.token.TokenException;
import com.github.highcumontoa.accessgatewayjava.token.TokenRejectReason;
import com.github.highcumontoa.accessgatewayjava.tests.support.TestGateway;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 密钥轮换：重叠期内旧令牌可用，重叠期结束后拒绝。
 * 边界取 rejectAfter 恰好相等与超出一秒两点，结论确定可复现。
 */
class KeyRotationTest {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationTest.class);

    @Test
    void oldKeyTokenValidDuringOverlapAndNewKeyUsedAfterRotation() {
        TestGateway gw = TestGateway.create();
        IssuedTokens before = gw.auth.login("alice", "alice-pass", "demo-api");
        String oldKid = gw.keyService.activeKeyId();
        log.info("输入: 轮换前签发令牌，activeKid={}", oldKid);

        gw.keyService.rotate();
        String newKid = gw.keyService.activeKeyId();
        log.info("判定依据: 轮换后 activeKid={}（旧密钥进入重叠期 {}s）", newKid, gw.props.getKey().getOverlapSeconds());
        assertNotEquals(oldKid, newKid);

        var verifiedOld = gw.codec.verify(before.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api");
        log.info("判定依据: 重叠期内旧密钥令牌校验通过 kid={}", verifiedOld.keyId());
        assertEquals(oldKid, verifiedOld.keyId());

        IssuedTokens after = gw.auth.login("alice", "alice-pass", "demo-api");
        var verifiedNew = gw.codec.verify(after.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api");
        log.info("判定依据: 轮换后新令牌使用新密钥 kid={}", verifiedNew.keyId());
        assertEquals(newKid, verifiedNew.keyId());
    }

    @Test
    void oldKeyTokenAcceptedAtOverlapBoundaryAndRejectedAfter() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        String refreshToken = tokens.refreshToken();
        long overlap = gw.props.getKey().getOverlapSeconds();

        gw.keyService.rotate();
        log.info("输入: 刷新令牌（TTL 足够长，排除自身过期干扰），重叠期={}s", overlap);

        gw.clock.advance(Duration.ofSeconds(overlap));
        var atBoundary = gw.codec.verify(refreshToken, TokenCodec.TYPE_REFRESH, null);
        log.info("判定依据: now == rejectAfter 边界上仍接受 kid={}", atBoundary.keyId());
        assertEquals("key-1", atBoundary.keyId());

        gw.clock.advance(Duration.ofSeconds(1));
        TokenException ex = assertThrows(TokenException.class,
                () -> gw.codec.verify(refreshToken, TokenCodec.TYPE_REFRESH, null));
        log.info("判定依据: now > rejectAfter 后拒绝 reason={} message={}", ex.getReason(), ex.getMessage());
        assertEquals(TokenRejectReason.KEY_OVERLAP_ENDED, ex.getReason());
    }

    @Test
    void newKeyTokenUnaffectedByOverlapEnd() {
        TestGateway gw = TestGateway.create();
        gw.keyService.rotate();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        log.info("输入: 轮换后签发的令牌，推进时钟超过旧密钥重叠期");

        gw.clock.advance(Duration.ofSeconds(gw.props.getKey().getOverlapSeconds() + 1));
        var verified = gw.codec.verify(tokens.refreshToken(), TokenCodec.TYPE_REFRESH, null);
        log.info("判定依据: 新密钥令牌不受旧密钥重叠期结束影响 kid={}", verified.keyId());
        assertEquals(gw.keyService.activeKeyId(), verified.keyId());
    }
}
