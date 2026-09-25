package com.github.highcumontoa.accessgatewayjava.auth;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 进程内身份库：预置演示用户，凭证校验与角色查询。
 *
 * <p>密码以 SHA-256 加盐摘要保存（仅本地模拟，非真实凭据方案）。
 * 角色只能从这里读取，客户端自报角色一律无效。
 */
@Service
public class CredentialService {

    private record UserEntry(String passwordHash, Set<String> roles) {
    }

    private static final String SALT = "local-demo-salt";

    private final Map<String, UserEntry> users = Map.of(
            "alice", new UserEntry(hash("alice-pass"), Set.of("reader")),
            "bob", new UserEntry(hash("bob-pass"), Set.of("writer")),
            "carol", new UserEntry(hash("carol-pass"), Set.of("reader", "writer")),
            "admin", new UserEntry(hash("admin-pass"), Set.of("admin"))
    );

    /** 校验用户名密码，成功返回该用户的服务端角色集合。 */
    public Optional<Set<String>> verify(String username, String password) {
        UserEntry entry = users.get(username);
        if (entry == null || password == null) {
            return Optional.empty();
        }
        if (!MessageDigest.isEqual(
                entry.passwordHash().getBytes(StandardCharsets.UTF_8),
                hash(password).getBytes(StandardCharsets.UTF_8))) {
            return Optional.empty();
        }
        return Optional.of(entry.roles());
    }

    /** 按用户名查询角色（刷新时重新取角色，保证角色以服务端为准）。 */
    public Optional<Set<String>> rolesOf(String username) {
        UserEntry entry = users.get(username);
        return entry == null ? Optional.empty() : Optional.of(entry.roles());
    }

    private static String hash(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] out = digest.digest((SALT + ":" + password).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
