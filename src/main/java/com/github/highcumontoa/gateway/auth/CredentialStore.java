package com.github.highcumontoa.gateway.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 进程内凭证库。口令只保存 SHA-256(盐 + 口令) 哈希；
 * 角色由服务端档案唯一维护，客户端无法在令牌请求中注入角色。
 */
@Component
public class CredentialStore {
    private final Map<String, UserAccount> users = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public CredentialStore() {
        addUser("alice", "alice-pass", List.of("reader"));
        addUser("bob", "bob-pass", List.of("reader", "writer"));
        addUser("admin", "admin-pass", List.of("reader", "writer", "admin"));
    }

    /** 校验凭证，成功返回用户档案；失败（用户不存在/口令错误/停用）返回空。 */
    public Optional<UserAccount> verify(String username, String password) {
        UserAccount account = users.get(username);
        if (account == null || !account.enabled() || password == null) {
            return Optional.empty();
        }
        return hash(password, account.salt()).equals(account.passwordHash())
                ? Optional.of(account) : Optional.empty();
    }

    public void addUser(String username, String password, List<String> roles) {
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        String salt = HexFormat.of().formatHex(saltBytes);
        users.put(username, new UserAccount(username, hash(password, salt), salt, List.copyOf(roles), true));
    }

    public Optional<UserAccount> find(String username) {
        return Optional.ofNullable(users.get(username));
    }

    private static String hash(String password, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] out = digest.digest((salt + ":" + password).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
