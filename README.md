# CheckinMyFreeAPI

提供 Go 独立应用和现有 Python 3.11 + aiohttp 版本, 共用 WebUI 与加密 SQLite 数据格式. 包含签到管理和登录后可见的 Status 余额面板. 只支持两个固定站点, 运行时不安装或启动任何浏览器, 不支持 OAuth、自定义站点或远程桌面.

Go 版无需安装 Python, 支持 Windows 静默后台运行、当前用户登录后自启、Windows/Linux 系统服务以及启动签到. 默认启动后等待 10 秒, 当天已确认成功的账号跳过; 暂停、限流与结果不确定规则继续生效. 在 `定时与网络 -> 本机启动与后台运行` 单独保存启动设置. 首次启动通过 http://127.0.0.1:8765 设置管理密码, 不会自动打开浏览器.

使用 Go 1.26.10 或更新补丁版本从源码构建:

```powershell
./scripts/build-go.ps1
./dist/go/windows-amd64/checkin.exe
```

Windows 的 `checkin.exe` 无命令行窗口, `checkin-cli.exe` 用于诊断和服务管理. Linux 提供 amd64/arm64 独立二进制, 可以用 `bash scripts/build-go.sh` 构建. 完整的运行、自启、服务、容器与旧数据迁移说明见 [Go 版使用说明](docs/go-edition.md). Python 版仍可按下文运行; 两个进程不能同时使用同一数据目录. 当前服务器的运行版本不会因为本地构建而改变.

管理认证保留密码登录与 Passkey 登录两种可选模式, 共用同一份程序和账户数据. 默认沿用密码模式, 绑定并验证 Passkey 后可自行切换, 无需部署两套服务.

| 站点 | 认证方式 | 请求行为 |
|---|---|---|
| anyrouter.top | Cookie + 用户 ID, 或站点用户名密码 | HTTP 登录/核验用户后 POST /api/user/sign_in, 再核对用户 |
| agentrouter.org | 仅站点用户名密码 | 每次运行使用新 HTTP 会话 POST /api/user/login?turnstile=, 核验登录响应的身份和签到状态 |

Agent 每次运行都重新登录, 不复用已保存登录会话, 不发送 /api/user/sign_in, 也不通过用户信息请求推断签到. 仅当登录响应 success 严格为 true, 身份核验通过, 且 data.checked_in 严格为 true 时, 才记录签到成功 (agent_checkin_verified). checked_in 严格为 false 时记录失败 (agent_checkin_not_confirmed); 缺失或类型异常时记录结果不确定 (agent_checkin_result_unknown); 登录拒绝为 password_login_rejected. 不展示登录响应中的余额或奖励字段. 当前只通过本地模拟测试, 尚未完成真实站点验收, 签到状态也不表示奖励到账.

## 本地运行

```powershell
uv sync --frozen
uv run --frozen python -m server
```

首次启动会设置管理密码, 并创建原始 32 字节主密钥. 默认访问 http://127.0.0.1:8765. 若该端口被系统保留或占用, 设置 CHECKIN_WEB_PORT. `checkin.py` 是相同 WebUI 的兼容入口, 不读取旧环境变量启动签到.

1. 登录后添加账号, 选择 AnyRouter 或 AgentRouter. 账号详情可折叠, 草稿在成功保存后生效.
2. Any Cookie 模式填写完整 Cookie header 和用户 ID; 密码模式填写目标站点用户名和密码, 可填写预期用户 ID/用户名加强核验. 不填写第三方平台密码.
3. Agent 只支持站点账号密码, 可填写预期用户 ID/用户名加强核验. 切换到 Agent 时默认使用账号密码, 切换站点或认证方式会清除草稿中不兼容的凭据. 旧 Agent 令牌账号升级后会停用, 请补填 AgentRouter 站点账号密码并保存, 核对后再启用.
4. 保存配置不会签到或发送通知. 确认配置后可点击开始签到运行全部启用账号, 或在已保存且启用的账号卡片上点击单账号签到. 有未保存修改、已有任务或状态尚未确认时不能启动, 单账号任务也遵守限流及结果不确定时的暂停规则. 验证真实站点结果后再启用定时任务.
5. 账号可禁用, 禁用后保留配置且不发站点请求. 定时任务默认关闭, 默认间隔 360 分钟, 也可选择固定时间 Cron; 不补跑停机期间任务.

Any Cookie 模式需要非空的 `session` 登录 Cookie. 推荐先在自己的浏览器登录 https://anyrouter.top, 按 F12 -> Application -> Cookies -> https://anyrouter.top, 找到 `session` 并复制其 Value, 在 WebUI 填写 `session=复制的值`. 也可在 Network 中选择已登录的站点请求, 从 Request Headers 手动复制包含 `session` 的完整 Cookie 值. `acw_sc__v2` 只是访问验证 Cookie, 不能替代登录 Cookie; WebUI 会拦截缺少非空 `session` 的新输入.

Cookie 认证仅支持手动粘贴, 不提供 Console 提取脚本或 cURL 导入. HttpOnly Cookie 无法通过普通页面脚本读取, 请使用上述开发者工具获取方式.

## 运行结果与人工处理

当前任务和近期运行显示已处理账号数、总账号数及当前账号的实际执行阶段. 展开账号结果后, 自动刷新保留展开状态, 可查看阶段记录、原因说明及原因代码、失败接口的方法和路径、HTTP 状态及网络异常类型. 原始响应体、异常原文和请求凭据不进入执行记录. 老记录没有这些新字段时仍可查看已有结果. 单账号运行只向执行进程传递所选账号的凭据, 不修改已保存配置或定时计划.

- 凭据失效: 暂停该账号的后续定时执行, 通知用户在自己的浏览器完成站点操作后更新 Cookie 或站点账号密码.
- AnyRouter 已知 acw 验证: 参考 Metapi, 静态解析完整已知挑战模板, 根据 arg1、排列表和 XOR 种子计算 acw_sc__v2, 合并同一 HTTP 会话收到的 Cookie. 每个登录或只读用户核验请求最多发送 3 次, 进度中显示验证阶段和请求次数. 不执行网页 JavaScript, 不引入 Node 或浏览器. 模板变化、Cookie 上下文缺失或达到上限时暂停并通知.
- 其他 CF/WAF/验证码: 暂停并通知, 不启动浏览器, 不自动处理验证码, 不更换出口重试. 用户在本机通过验证不能保证服务器出口也能使用该凭据. Any 签到 POST 和 Agent 登录 POST 不进行 acw 重发; 返回 acw 页时结果需人工核对后解除暂停.
- 限流: 遵守 Retry-After, 期限内包括手动运行也不重发请求; 未提供有效期限时保守等待一小时.
- 写入结果不确定: 包括签到超时、异常响应或任务中断, 不自动重发. 在站点核对后通过账号卡片的 `已核对结果, 解除暂停` 明确恢复. 更新凭据本身也不会解除这种不确定状态.
- 普通网络/服务故障: 显示固定原因代码, 本次任务不重试. 后续独立定时任务可重新尝试安全的读取流程.

Any 密码登录会优先复用已验证、加密保存的 HTTP 会话; 失效后最多尝试一次 API 登录. 签到前核对账号, 签到后再次核对, 失败不覆盖上一份会话. HTTP 不跟随重定向, 凭据只发送到账号选定的固定站点.

Agent 签到不复用已保存会话. 登录请求带空 turnstile 查询参数, 在当次新 HTTP 会话内完成请求和身份核验. 启用余额监测后, 正常登录产生的会话加密保存, 仅供后续只读余额查询; 登录响应中的占位额度不作为真实余额. 余额采集失败不会将已确认的签到改判为失败. 历史 user_info_requested_reward_unverified 记录保留原有说明, 仅表示当时用户信息请求完成, 未验证签到; 不因升级改写为签到成功.

## Status 余额面板

登录后通过 Status 入口或 `/status` 查看各账户余额、今日新增、今日净变化、总余额及最近 30 天记录. Status 与管理面板共用管理认证, 不向未登录访问者公开账户统计.

- 余额监测默认开启, 每 60 分钟采集一次, 在定时与网络中配置开关和间隔. 打开页面和页面轮询只读取缓存, 手动刷新按钮才创建采集任务. 采集与签到共用串行任务锁, 避免同时操作账户会话.
- 通过 `GET /api/user/self` 读取真实余额, Any/Agent 原始额度按每 500000 单位折算为 1 单位站内美元额度. 总余额汇总当前启用账户的最近已知余额, 同时显示采集覆盖数和过期状态; 不是现金资产估值.
- 今日新增优先使用站点有效的 `today_income`, 缺失时根据同日已观测的剩余额度和累计消耗变化计算入账. 首次采样不虚构收入. 部分时段结果标明观察范围, 不声称覆盖全天.
- 今日净变化以同日首个观测余额为基准, 包含消费影响. 日期按 `Asia/Singapore` (UTC+8) 划分, 未采集的历史不补造, 跨日缺失基准不借用旧值冒充当天完整统计.
- 查询失败保留上次成功余额并标记错误或过期. 未知值显示未知, 与真实 0 区分. 更改凭据、目标身份或代理后不会复用不匹配的历史基准和会话.
- 余额采集不调用签到接口, 也不自动通过账号密码登录. Any Cookie 可直接查询; 密码账号及 Agent 在正常签到建立会话后可查询. 会话失效需要更新 Cookie 或等待正常签到恢复. CF、限流和结果不确定的暂停规则继续生效, 余额刷新不会解除签到暂停.

站点代理在 WebUI 的 `定时与网络 -> 默认代理` 配置. 单个账号也可展开 `账号代理`, 选择沿用上级、直连、默认代理或指定代理. 支持 HTTP、HTTPS 和 SOCKS5, 包括 `socks5://用户名:密码@主机:1080`. 使用 SOCKS5 认证时, 用户名和密码均需填写, URL 解码后各为 1 至 255 个 UTF-8 字节; 无认证 SOCKS5 仍可使用. 特殊字符应进行百分号编码, 例如用户名 `user@example`、密码 `pass:word@` 可写为 `socks5://user%40example:pass%3Aword%40@proxy.example:1080`. URL 和其中的凭据加密保存, 已保存值不会回显. 代理认证失败会显示明确错误, 不会自动改为直连. 登录、acw 验证及签到沿用同一代理会话. 该设置用于站点请求, 通知渠道的网络设置保持现有行为.

通知渠道包含 Fy1Push、邮件、Telegram、Bark、Gotify、PushPlus、Server 酱、钉钉、飞书和企业微信. Fy1Push 使用 HTTPS 地址与发送 token, token 不写日志. `accepted` 只表示服务端接收, 不保证手机送达. 相同待处理结果不反复通知; 配置变化、状态变化或通知失败可触发后续发送. 可配置 WebUI 地址, 通知中的链接只携带账号 ID, 不包含密码、Cookie 或 token. WebUI 仍需管理密码登录. 私有 SSH 转发场景按实际转发地址打开.

## 数据与旧配置迁移

配置、HTTP 会话均通过独立用途的 AES-GCM 加密保存于 SQLite. 管理密码只保存加盐哈希. 执行记录和暂停原因不是全部加密, 整个数据目录仍应私有保存. 输入框隐藏已保存秘密, 留空保留, 点击清除才删除. 修改凭据使旧 HTTP 会话绑定失效, 不会误复用其他账号的会话.

浏览器旧版配置在取得服务独占锁后迁移: 先在同一数据库事务内归档原始密文与版本, 再生成当前格式配置, 关闭旧定时任务. 支持转换的 Any Cookie/密码账号保留; OAuth 等不支持的认证转换为禁用待配置. 不支持的自定义站点仅从活动配置中移除, 原始内容保留在加密归档. 旧浏览器加密快照和历史记录不删除, 新执行器不读取或跨平台导入它们.

已有 HTTP 版本升级时, 旧 Agent 系统令牌账号保留账号 ID、名称、身份核验信息和代理等账户配置, 改为停用的账号密码模式, 清除活动配置中的不兼容凭据, 等待用户补填站点账号密码. 原始配置仍保留在加密归档中. Any 账号、会话、历史、代理和定时配置均保留; 只有迁移后不存在任何启用账号时才同时关闭定时. 不会自动清空所有已保存数据.

迁移会增加配置版本. 若需要回退, 在首次启动新版本前停止服务, 备份整个数据目录与独立 master.key. 数据和密钥分开保管, 不更换密钥来重置已有数据. 本版本支持加密备份的图形化预览恢复, 不提供直接修改主密钥的入口.

## 定时、告警与每日摘要

- 定时与网络支持间隔或五字段 Cron, 按 UTC+8 执行. 例如 `0 8 * * *` 为每天 08:00, `0 */12 * * *` 为每天 00:00 和 12:00. 支持数字、逗号、范围和步长, 星期 0/7 为周日; 同时指定日期和星期时使用标准 OR 语义. 最短间隔 30 分钟, 不支持秒字段、名称或非标准扩展. 升级保留原间隔模式和原定时计划.
- 低余额通知默认关闭, 在通知配置中启用并设置全局阈值与冷却时间. 账户可以独立设置阈值, 留空继承全局. 仅使用新鲜、成功核验的余额, 未知/过期/停用账号不触发低余额告警; 消费后的真实余额回升会重新建立下一次低余额事件.
- 故障恢复通知默认关闭. 分别追踪签到与余额查询的真实失败、首次异常时间、连续失败和恢复时间. 首次成功不当作故障恢复, 跳过的任务不冒充成功. 余额查询成功不会解除签到结果不确定的暂停.
- 每日摘要默认关闭, 默认时间 23:55 UTC+8. 摘要读取已保存的余额、当日签到记录及健康状态, 不额外登录或发起签到. 可以手动发送今日摘要, 同一天的发送采用持久去重; 发送结果不确定时不自动重发. 首日或数据缺失时明确标注未知、覆盖数与观察期, 不把部分收入当作完整全天收益.
- 自动通知复用现有通知渠道, 包括 Fy1Push. 最近发送记录区分渠道接受、部分接受、失败、无渠道和结果不确定. 渠道接受不表示设备已收到. 配置保存本身不发送通知, 新增告警与摘要在用户启用后生效.

## 加密备份与恢复

通过 `/backups` 或管理面板的备份与恢复入口操作. 备份配置包括每日时间、保留份数和独立恢复密码; 自动备份默认关闭, 需要先保存 16..512 字符的恢复密码. 恢复密码作为敏感配置加密保存且不回显, 与管理员登录密码用途不同.

备份文件 `.nab` 使用 scrypt 派生密钥和 AES-GCM 加密, 包含 SQLite 一致快照、原始主密钥和格式校验信息. 本地轮换默认保留 7 份, 支持 1..90 份. 只有成功创建新备份后才执行轮换; 备份与签到/余额/摘要共用任务锁. 更改恢复密码仅影响之后创建的备份. 文件默认保存在数据卷的 `backups/`, 可下载到其他设备保存. 同盘备份不能防止整块磁盘丢失.

WebUI 恢复先上传不超过 64 MiB 的备份并输入其恢复密码. 服务校验格式、SQLite 完整性、受信表结构及加密数据后显示预览, 当前数据尚不替换. 预览凭据十分钟有效、单次使用且绑定配置版本. 最后输入当前管理员密码并明确确认, 才先备份现有数据、停止自动任务并替换数据库. 恢复前快照使用当前已保存的恢复密码, 尚未配置时使用本次输入的恢复密码.

同一实例恢复会将备份内配置、归档和会话重新加密到当前主密钥, 保留当前管理员密码和管理 URL, 无需改写容器的只读密钥挂载. 恢复后自动签到、余额监测、自动通知和自动备份均关闭, 管理会话作废, 需重新登录核对后启用. 原有未知写入暂停保留. 替换或重新打开失败时恢复替换前数据库, 不将一次余额成功作为恢复未知签到的证据.

同一实例恢复同时保留当前登录模式和 Passkey, 包括公钥、计数器和认证用户标识, 不从旧备份重新启用密码登录或恢复已删除的密钥. 恢复身份校验使用当前模式: 密码模式重验管理员密码, 公网 Passkey 模式必须进行一次新的 Passkey 验证. 离线灾难恢复保留备份中的认证设置, 域名变化导致原密钥不可用时使用 SSH 恢复工具重新配置.

灾难恢复工具可以在原服务器和主密钥丢失后, 使用下载的 `.nab` 与独立恢复密码检查和恢复到空目录. 通过 `python -m server.backup_cli --help` 查看参数, 密码在终端提示中输入, 不放入命令参数. 离线工具拒绝覆盖已有数据库或密钥, 恢复后同样关闭自动任务. 上传校验和恢复操作均不会调用站点或发送通知.

## 启动配置

| 环境变量 | 默认值/说明 |
|---|---|
| CHECKIN_WEB_HOST | 127.0.0.1, 容器内部可为 0.0.0.0 |
| CHECKIN_WEB_PORT | 8765 |
| CHECKIN_WEB_DATA_DIR | server-data |
| CHECKIN_WEB_KEY_FILE | server-keys/master.key, 原始 32 字节 |
| CHECKIN_WEB_PASSWORD_FILE | 首次管理密码的只读文本文件, 至少 16 字符 |
| CHECKIN_WEB_PASSWORD | 首次密码的备选进程环境来源, 优先使用密码文件 |
| CHECKIN_WEB_PUBLIC_URL | 可选的公网 HTTPS origin, 如 https://checkin.example.com; 默认只允许本机或 SSH 转发 |
| CHECKIN_WEB_TRUSTED_PROXY_IPS | 可选的可信反向代理单 IP 列表; 只接受这些来源提供的转发头 |

账号、通知、代理与定时配置全部通过 WebUI 保存. 服务不自动读取 .env, 不支持旧 --import-env 参数. 缺少现有数据库所对应的密钥时拒绝启动.

## Linux 容器

Dockerfile 的生产依赖只有 HTTP、加密和 WebUI 库, 没有 Playwright、Chromium、CloakBrowser、Xvfb、noVNC 或浏览器共享内存配置. 单实例容器通过 bind mount 持久化数据和密钥. 需先准备 `server-keys/master.key` 和 `server-keys/web-password`, 文件允许容器 UID/GID 10001 读取.

从本地迁移时先关闭定时任务并停止本地服务, 备份并复制完整 SQLite 数据目录、原 `master.key` 和管理密码文件, 保持原管理密码. 不要执行下面的新密钥生成命令覆盖原密钥. 初次服务器验证期间保持定时关闭, 确认配置、代理和手动运行结果后再启用. 站点代理通过 WebUI 配置并加密保存, 不将代理密码写入 Compose、环境变量或镜像.

仅首次创建空白实例时生成新密钥:

```bash
mkdir -p server-keys
python3 -c "from pathlib import Path; import secrets; Path('server-keys/master.key').write_bytes(secrets.token_bytes(32))"
# 使用本机安全编辑器创建 server-keys/web-password, 不把真实密码写进 shell 历史.
chmod 700 server-keys
chmod 600 server-keys/master.key server-keys/web-password
sudo chown -R 10001:10001 server-keys
docker compose up --build -d
```

默认 Python 基础镜像为 `python:3.11-slim-bookworm`. 若服务器无法访问 Docker Hub, 可覆盖为兼容的 Python 3.11 基础镜像, 例如从 GHCR 构建. uv 二进制仍从固定版本 `ghcr.io/astral-sh/uv:0.11.10` 复制:

```bash
docker compose build --build-arg PYTHON_IMAGE=ghcr.io/astral-sh/uv:python3.11-bookworm-slim
docker compose up --no-build -d
```

正式部署可将已核验的基础镜像固定为 `镜像名@sha256:摘要`, 以便重复构建.

Compose 将容器 8765 仅映射到宿主 127.0.0.1:8765. 在本机建立转发:

```bash
ssh -N -L 127.0.0.1:18765:127.0.0.1:8765 your-server
```

然后通过 http://127.0.0.1:18765 管理. 本机端口被占用时可更换转发左侧端口. 默认服务只接受 loopback Host.

### 公网 HTTPS 管理

继续将应用端口绑定在宿主 loopback, 通过 Caddy 等反向代理提供 HTTPS. 在 Compose 的应用环境中设置 `CHECKIN_WEB_PUBLIC_URL=https://checkin.example.com`, 并将 `CHECKIN_WEB_TRUSTED_PROXY_IPS` 配置为应用实际看到的反向代理 IP (Docker bridge 下通常为宿主网关单 IP). 不将任意来源或整个网段列为可信代理.

```caddyfile
checkin.example.com {
    reverse_proxy 127.0.0.1:8765 {
        header_up X-Forwarded-Proto https
        header_up X-Forwarded-For {remote_host}
    }
}
```

应用只接受显式配置的公网 origin, 不用访问者提供的转发 Host 自动扩展可信域名. 公网管理 Cookie 为 Secure、HttpOnly、SameSite=Strict, 会话绑定访问 origin; 修改请求还校验 Origin 和 CSRF. 登录使用按来源及全局限流、限制密码哈希并发. SSH 本机访问仍可使用, 与公网会话隔离. 反向代理需保留原始 Host 并覆盖转发协议与来源头, 不暴露容器明文管理端口. DNS 指向正确源站后再启用入口, 证书签发和域名可达性需在实际部署环境核验.

### 可选的密码版与 Passkey 版

在 `/security` 或登录安全入口选择管理认证模式. 两种模式长期共用同一套签到、监测和备份能力, 模式设置独立于普通账户配置保存.

- 密码模式: 保留当前管理员密码登录和登录限流, 兼容已有部署; 已绑定的 Passkey 也可用于登录. 首次部署应使用至少 16 字符的随机管理密码.
- Passkey 模式: 公网只接受 Passkey 登录, 同时关闭公网密码登录及密码二次验证入口. 备份恢复、密钥管理和模式切换使用当前策略要求的新鲜验证, 不保留弱密码旁路.
- 首次绑定: 通过配置的 HTTPS 管理入口登录, 打开登录安全, 重验当前管理员身份后添加密钥. 支持 Windows Hello、手机 Passkey 和兼容的硬件安全密钥. 注册后再完成一次 Passkey 验证, 才允许切换到 Passkey 模式.
- 可保存最多 10 个命名密钥. Passkey 模式下不能删除最后一个已验证密钥; 需要先添加备用密钥或明确切回密码模式. 切回密码模式会重新开启公网密码入口, 页面会明确确认.
- 密钥绑定注册时的 RP ID 和精确 origin. 服务器只保存公钥及必要元数据, 不保存认证器私钥或生物识别信息. 域名或协议、端口改变时, 原注册关系可能无法使用; 不将任意反向代理请求头作为可信 RP ID.
- WebAuthn 验证由 Yubico 的 [python-fido2](https://github.com/Yubico/python-fido2) 实现. 请求使用短期、单次挑战, 校验 origin、RP ID、用户存在与用户验证标记、签名和计数器. 模式变化撤销旧管理会话, 注册和删除密钥均需再次验证身份.

启用 Passkey 前, 应确保已有至少一个验证成功的密钥并保留 SSH 管理能力. 新版本升级不会自动切换现有认证方式, 也不会代替用户创建真实 Passkey.

### 通过 SSH 恢复登录

本机或 SSH 隧道的受限入口仍可使用管理员密码恢复管理. 公网请求不能通过伪造 Origin、Host 或转发头调用这个恢复路径. 若密钥全部丢失或域名变更, 可在 SSH 中停止服务后运行恢复工具; 工具必须取得服务数据目录的独占锁, 不与在线实例同时修改认证状态:

```bash
docker compose stop checkin
docker compose run --rm --no-deps --entrypoint /opt/venv/bin/python checkin \
  -m server.security_cli reset --data-dir /data --confirm
docker compose up --no-build -d checkin
```

该操作恢复密码模式并使旧管理会话失效, 保留账户、签到历史、余额和备份. 添加 `--clear-passkeys` 可同时撤销全部已保存密钥. 重置后使用现有管理密码重新绑定并验证密钥, 再选择是否启用 Passkey 模式. 工具不更改管理员密码、不调用站点、不发送通知.

Windows 已有本地测试实例可手动运行 `scripts/restart_local_webui.ps1 -TestRoot <测试目录>`. 脚本先检查无任务且定时关闭, 核对监听进程归属, 才重启. 加 `-CheckOnly` 只检查. 不删除数据、不自动签到、不切换浏览器选项. 服务启动后按上述规则迁移旧配置.

也可运行 `scripts/update-local-webui.cmd "测试目录" "仓库目录"`, 窗口会保留成功或失败信息. 更新过程从启动时显示分阶段进度, 登录、状态和配置请求默认最多等待 8 秒, 可通过 PowerShell 参数 `-RequestTimeoutSeconds` 调整. 普通更新将进度和错误追加到测试目录的 `update.log`, 服务启动错误见 `stderr.log`; `-CheckOnly` 不写日志或重启服务. 启动时进程提前退出会立即提示, 不静默等待.

## 开发验证

```bash
uv run --frozen pytest tests/ -q -o addopts=''
uv run --frozen ruff check . --no-fix
uv run --frozen ruff format --check .
uv run --frozen mypy . --ignore-missing-imports
uv run --frozen bandit -r . -c pyproject.toml
```

Playwright 只在 dev 依赖中, 用于隔离 WebUI 测试, 不用于产品运行. 可设置 CHECKIN_BROWSER_TESTS=1 运行浏览器界面回归; CI 只安装测试浏览器并使用本地模拟服务. 不配置真实站点凭据或通知 token. GitHub Actions 仅做代码检查和模拟测试, 不运行真实签到. 自动化测试通过不表示 Any/Agent 当前线上接口、风控或奖励到账已验收.

## 参考源码

- https://github.com/millylee/anyrouter-check-in
- https://github.com/Fy1ng/newapi-ai-check-in

当前实现已按 HTTP-only v1 范围重构, 不等同于参考仓库当前版本. acw 定向处理另参考 https://github.com/cita-777/metapi. 许可证见 LICENSE, 第三方来源与许可见 THIRD_PARTY_NOTICES.md.
