package com.github.highcumontoa.gateway.session;

/** 会话（族）当前状态。 */
public enum SessionState {
    /** 活跃：刷新与访问均正常。 */
    ACTIVE,
    /** 已终止：被用户主动下线或被管理操作吊销。 */
    TERMINATED
}
