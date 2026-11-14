#!/bin/sh
# repairs/users_repair.sh - User account repairs

lg_repair_uid0_users() {
    printf '  Will not automatically delete or modify UID 0 accounts / 不会自动删除或修改 UID 0 账户。\n'
    printf '  Review accounts manually and remove unauthorized UID 0 entries from /etc/passwd / 请手动检查账户并从 /etc/passwd 中移除非授权的 UID 0 条目。\n'
    return 1
}

lg_repair_empty_passwords() {
    printf '  Will not automatically lock accounts without passwords / 不会自动锁定无密码账户。\n'
    printf '  Use "passwd -l <user>" or set a strong password for each affected account / 使用 "passwd -l <user>" 或为每个受影响账户设置强密码。\n'
    return 1
}

lg_repair_unusual_shell() {
    printf '  Will not automatically change user shells / 不会自动更改用户 Shell。\n'
    printf '  Review accounts and set correct shells with "chsh <user>" / 请检查账户并使用 "chsh <user>" 设置正确的 Shell。\n'
    return 1
}

lg_repair_stale_passwords() {
    printf '  Will not automatically change passwords / 不会自动更改密码。\n'
    printf '  Prompt affected users to update passwords or enforce password expiration policy / 提示受影响用户更新密码或强制密码过期策略。\n'
    return 1
}
