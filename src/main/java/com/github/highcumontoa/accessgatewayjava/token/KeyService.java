package com.github.highcumontoa.accessgatewayjava.token;

import com.github.highcumontoa.accessgatewayjava.config.GatewayProperties;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 进程内签名密钥库。
 *
 * <p>密钥由本地种子按 kid 派生（HMAC-SHA256(seed, "key:"+kid)），不落盘、不依赖外部服务。
 * 轮换时旧密钥进入重叠接受期：在 rejectAfter 之前旧密钥签署的令牌仍可校验，
 * 超过 rejectAfter 后一律以 {@link TokenRejectReason#KEY_OVERLAP_ENDED} 拒绝。
 */
@Service
public class KeyService {

    private final GatewayProperties props;
    private final Clock clock;
    private final Map<String, byte[]> keys = new ConcurrentHashMap<>();
    private final Map<String, KeyInfo> infos = new ConcurrentHashMap<>();
    private final AtomicInteger sequence = new AtomicInteger();
    private volatile String activeKid;

    public KeyService(GatewayProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
        String kid = nextKid();
        keys.put(kid, derive(kid));
        infos.put(kid, new KeyInfo(kid, clock.instant(), null, null));
        this.activeKid = kid;
    }

    private String nextKid() {
        return "key-" + sequence.incrementAndGet();
    }

    private byte[] derive(String kid) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(props.getKey().getSeed().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(("key:" + kid).getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("无法派生签名密钥", e);
        }
    }

    /** 当前在用密钥编号。 */
    public String activeKeyId() {
        return activeKid;
    }

    /** 当前在用密钥字节。 */
    public byte[] activeKey() {
        return keys.get(activeKid);
    }

    /** 按 kid 取密钥字节；不存在返回 null。 */
    public byte[] keyById(String kid) {
        return kid == null ? null : keys.get(kid);
    }

    /** 按 kid 取元数据；不存在返回 null。 */
    public KeyInfo infoById(String kid) {
        return kid == null ? null : infos.get(kid);
    }

    /**
     * 轮换：生成新密钥并将在用密钥退役，旧密钥进入重叠接受期。
     * 同步方法保证并发轮换时密钥状态一致。
     */
    public synchronized KeyInfo rotate() {
        Instant now = clock.instant();
        KeyInfo old = infos.get(activeKid);
        infos.put(old.kid(), new KeyInfo(old.kid(), old.createdAt(), now,
                now.plusSeconds(props.getKey().getOverlapSeconds())));
        String kid = nextKid();
        keys.put(kid, derive(kid));
        KeyInfo fresh = new KeyInfo(kid, now, null, null);
        infos.put(kid, fresh);
        activeKid = kid;
        return fresh;
    }

    /** 只读视图（按创建时间排序，, 供管理接口展示）。 */
    public List<KeyInfo> listKeys() {
        return infos.values().stream()
                .sorted(Comparator.comparing(KeyInfo::createdAt).thenComparing(KeyInfo::kid))
                .toList();
    }
}
