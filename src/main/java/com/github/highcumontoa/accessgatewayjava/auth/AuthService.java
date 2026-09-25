package com.github.highcumontoa.accessgatewayjava.auth;

import com.github.highcumontoa.accessgatewayjava.config.GatewayProperties;
import com.github.highcumontoa.accessgatewayjava.token.TokenCodec;
import com.github.highcumontoa.accessgatewayjava.token.VerifiedToken;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 认证门面：凭证校验、令牌签发、刷新与吊销。
 *
 * <p>角色来源规则：登录时取身份库角色；刷新时重新读取身份库当前角色
 * （身份库缺失时回退到会话族快照）。任何客户端自报角色均不参与签发。
 */
@Service
public class AuthService {

    private final CredentialService credentials;
    private final SessionService sessions;
    private final TokenCodec codec;
    private final GatewayProperties props;
    private final Clock clock;
    private final AtomicLong accessSequence = new AtomicLong();

    public AuthService(CredentialService credentials, SessionService sessions,
                       TokenCodec codec, GatewayProperties props, Clock clock) {
        this.credentials = credentials;
        this.sessions = sessions;
        this.codec = codec;
        this.props = props;
        this.clock = clock;
    }

    /** 凭证校验并签发令牌对。 */
    public IssuedTokens login(String username, String password, String audience) {
        Set<String> roles = credentials.verify(username, password)
                .orElseThrow(() -> new AuthException(AuthError.INVALID_CREDENTIALS, "用户名或密码错误"));
        String aud = (audience == null || audience.isBlank()) ? props.getDefaultAudience() : audience;

        String refreshJti = sessions.createFamily(username, aud, roles);
        String familyId = sessions.familyOf(refreshJti).getFamilyId();

        Instant now = clock.instant();
        Instant accessExp = now.plusSeconds(props.getToken().getAccessTtlSeconds());
        Instant refreshExp = now.plusSeconds(props.getToken().getRefreshTtlSeconds());

        String accessToken = mint(TokenCodec.TYPE_ACCESS, username, aud,
                "at-" + accessSequence.incrementAndGet(), now, accessExp, roles);
        String refreshToken = mint(TokenCodec.TYPE_REFRESH, username, aud,
                refreshJti, now, refreshExp, Set.of());
        return new IssuedTokens(accessToken, accessExp, refreshToken, refreshExp, familyId);
    }

    /**
     * 刷新令牌轮换并签发新令牌对。
     * 令牌本身的签名校验失败抛 {@link com.github.highcumontoa.accessgatewayjava.token.TokenException}；
     * 会话状态失败抛 {@link AuthException}。
     */
    public IssuedTokens refresh(String refreshToken) {
        VerifiedToken verified = codec.verify(refreshToken, TokenCodec.TYPE_REFRESH, null);
        String presentedJti = verified.claims().getTokenId();

        RefreshFamily family = sessions.familyOf(presentedJti);
        if (family == null) {
            throw new AuthException(AuthError.FAMILY_NOT_FOUND,
                    "刷新令牌编号不属于任何会话族: " + presentedJti);
        }
        if (!family.getAudience().equals(verified.claims().getAudience())) {
            throw new AuthException(AuthError.INVALID_REFRESH_TOKEN,
                    "刷新令牌受众与会话族不一致: " + verified.claims().getAudience());
        }

        SessionService.RotateOutcome outcome = sessions.rotate(presentedJti);

        Set<String> roles = credentials.rolesOf(outcome.subject()).orElse(outcome.roles());
        Instant now = clock.instant();
        Instant accessExp = now.plusSeconds(props.getToken().getAccessTtlSeconds());
        Instant refreshExp = sessions.familyOf(outcome.newRefreshTokenId()).getExpiresAt();

        String accessToken = mint(TokenCodec.TYPE_ACCESS, outcome.subject(), outcome.audience(),
                "at-" + accessSequence.incrementAndGet(), now, accessExp, roles);
        String newRefreshToken = mint(TokenCodec.TYPE_REFRESH, outcome.subject(), outcome.audience(),
                outcome.newRefreshTokenId(), now, refreshExp, Set.of());
        return new IssuedTokens(accessToken, accessExp, newRefreshToken, refreshExp, outcome.familyId());
    }

    /** 吊销指定会话族。 */
    public boolean revoke(String familyId) {
        return sessions.revokeFamily(familyId, "explicit-revoke");
    }

    private String mint(String type, String subject, String audience, String jti,
                        Instant now, Instant expiresAt, Set<String> roles) {
        com.github.highcumontoa.accessgatewayjava.token.TokenClaims claims =
                new com.github.highcumontoa.accessgatewayjava.token.TokenClaims();
        claims.setIssuer(props.getIssuer());
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setTokenId(jti);
        claims.setTokenType(type);
        claims.setIssuedAt(now);
        claims.setNotBefore(now);
        claims.setExpiresAt(expiresAt);
        claims.setRoles(roles);
        return codec.encode(claims);
    }
}
