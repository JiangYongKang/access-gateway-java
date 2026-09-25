package com.github.highcumontoa.accessgatewayjava.token;

import java.time.Instant;

/**
 * 一个签名密钥的元数据。
 *
 * @param kid          密钥编号
 * @param createdAt    创建时间
 * @param retiredAt    被轮换（退役）时间；null 表示当前在用
 * @param rejectAfter  退役后的重叠接受截止时间；null 表示当前在用
 */
public record KeyInfo(String kid, Instant createdAt, Instant retiredAt, Instant rejectAfter) {

    public boolean active() {
        return retiredAt == null;
    }
}
