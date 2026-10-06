package com.github.highcumontoa.gateway.token;

import java.time.Clock;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.session.SessionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 刷新令牌门面：保持既有对外方法签名（登录/刷新/吊销/测试观察），
 * 真正的会话族状态与轮换原子判定全部委托给 {@link SessionService}。
 *
 * <p>说明：自本轮起“刷新令牌记录”属于会话族状态的一部分，由 SessionService 统一持有，
 * 因此会话下线、闲置/总寿命判定与刷新消耗之间共享同一把会话锁，结果确定。
 */
@Service
public class RefreshTokenService {

    private final SessionService sessionService;

    /** 生产构造：使用容器中的权威 SessionService 单例（与会话管理端点共享状态）。 */
    @Autowired
    public RefreshTokenService(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    /** 兼容构造：旧调用方/单测仍可用四参直接装配（内部自建 SessionService 与审计日志）。 */
    public RefreshTokenService(GatewayProperties properties, JwtService jwtService,
                               CredentialStore credentialStore, Clock clock) {
        this(new SessionService(properties, clock, new AuditLog(), jwtService, credentialStore));
    }

    /** 凭证校验通过后签发初始令牌对：{accessToken, refreshToken}。 */
    public String[] issueInitialTokenPair(String username) {
        String[] triple = sessionService.openSession(username);
        return new String[]{triple[0], triple[1]};
    }

    /** 轮换刷新令牌。失败原因可区分，见 {@link RefreshFailureReason}。 */
    public RefreshResult rotate(String refreshToken) {
        return sessionService.rotate(refreshToken);
    }

    /** 显式吊销该令牌所属会话族。 */
    public void revokeFamily(String refreshToken) {
        sessionService.revokeFamilyByToken(refreshToken);
    }

    /** 仅供测试/审计观察：会话族是否已被吊销。 */
    public boolean isFamilyRevoked(String refreshToken) {
        return sessionService.isFamilyRevokedByToken(refreshToken);
    }
}
