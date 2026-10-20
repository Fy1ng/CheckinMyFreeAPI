# NewAPI HTTP 签到控制台

Python 3.11 + aiohttp + SQLite 的私有 WebUI. 第一版只支持两个固定站点, 服务器不安装或启动任何浏览器, 不支持 OAuth、自定义站点或远程桌面.

| 站点 | 认证方式 | 请求行为 |
|---|---|---|
| anyrouter.top | Cookie + 用户 ID, 或站点用户名密码 | HTTP 登录/核验用户后 POST /api/user/sign_in, 再核对用户 |
| agentrouter.org | 系统访问令牌 + 用户 ID | 单次 GET /api/user/self, 不额外发送签到 POST |

Agent 的自动签到行为来自参考项目, 当前没有执行真实站点验收. 用户信息请求成功只说明接口和身份核验完成, 不证明奖励到账. 系统访问令牌是站点控制台的账户凭据, 不等同于模型调用 API key. 站点当前是否接受该认证方式需要实际确认.

## 本地运行

```powershell
uv sync --frozen
uv run --frozen python -m server
```

首次启动会设置管理密码, 并创建原始 32 字节主密钥. 默认访问 http://127.0.0.1:8765. 若该端口被系统保留或占用, 设置 CHECKIN_WEB_PORT. `checkin.py` 是相同 WebUI 的兼容入口, 不读取旧环境变量启动签到.

1. 登录后添加账号, 选择 AnyRouter 或 AgentRouter. 账号详情可折叠, 草稿在成功保存后生效.
2. Any Cookie 模式填写完整 Cookie header 和用户 ID; 密码模式填写目标站点用户名和密码, 可填写预期用户 ID/用户名加强核验. 不填写第三方平台密码.
3. Agent 只能填写系统访问令牌和用户 ID. 切换站点或认证方式会清除草稿中不兼容的凭据.
4. 保存配置不会签到或发送通知. 确认配置后可点击开始签到运行全部启用账号, 或在已保存且启用的账号卡片上点击单账号签到. 有未保存修改、已有任务或状态尚未确认时不能启动, 单账号任务也遵守限流及结果不确定时的暂停规则. 验证真实站点结果后再启用定时任务.
5. 账号可禁用, 禁用后保留配置且不发站点请求. 定时任务默认关闭, 默认间隔 360 分钟, 不补跑停机期间任务.

Any Cookie 模式需要非空的 `session` 登录 Cookie. 推荐先在自己的浏览器登录 https://anyrouter.top, 按 F12 -> Application -> Cookies -> https://anyrouter.top, 找到 `session` 并复制其 Value, 在 WebUI 填写 `session=复制的值`. 也可在 Network 中选择已登录的站点请求, 从 Request Headers 手动复制包含 `session` 的完整 Cookie 值. `acw_sc__v2` 只是访问验证 Cookie, 不能替代登录 Cookie; WebUI 会拦截缺少非空 `session` 的新输入.

Cookie 认证仅支持手动粘贴, 不提供 Console 提取脚本或 cURL 导入. HttpOnly Cookie 无法通过普通页面脚本读取, 请使用上述开发者工具获取方式.

## 运行结果与人工处理

当前任务和近期运行显示已处理账号数、总账号数及当前账号的实际执行阶段. 展开账号结果后, 自动刷新保留展开状态, 可查看阶段记录、原因说明及原因代码、失败接口的方法和路径、HTTP 状态及网络异常类型. 原始响应体、异常原文和请求凭据不进入执行记录. 老记录没有这些新字段时仍可查看已有结果. 单账号运行只向执行进程传递所选账号的凭据, 不修改已保存配置或定时计划.

- 凭据失效: 暂停该账号的后续定时执行, 通知用户在自己的浏览器完成站点操作后更新 Cookie 或令牌.
- AnyRouter 已知 acw 验证: 参考 Metapi, 静态解析完整已知挑战模板, 根据 arg1、排列表和 XOR 种子计算 acw_sc__v2, 合并同一 HTTP 会话收到的 Cookie. 每个登录或只读用户核验请求最多发送 3 次, 进度中显示验证阶段和请求次数. 不执行网页 JavaScript, 不引入 Node 或浏览器. 模板变化、Cookie 上下文缺失或达到上限时暂停并通知.
- 其他 CF/WAF/验证码: 暂停并通知, 不启动浏览器, 不自动处理验证码, 不更换出口重试. 用户在本机通过验证不能保证服务器出口也能使用该凭据. 签到 POST 和 Agent 用户信息请求不进行 acw 重发; 返回 acw 页时结果需人工核对后解除暂停.
- 限流: 遵守 Retry-After, 期限内包括手动运行也不重发请求; 未提供有效期限时保守等待一小时.
- 写入结果不确定: 包括签到超时、异常响应或任务中断, 不自动重发. 在站点核对后通过账号卡片的 `已核对结果, 解除暂停` 明确恢复. 更新凭据本身也不会解除这种不确定状态.
- 普通网络/服务故障: 显示固定原因代码, 本次任务不重试. 后续独立定时任务可重新尝试安全的读取流程.

Any 密码登录会优先复用已验证、加密保存的 HTTP 会话; 失效后最多尝试一次 API 登录. 签到前核对账号, 签到后再次核对, 失败不覆盖上一份会话. HTTP 不跟随重定向, 凭据只发送到账号选定的固定站点.

站点代理在 WebUI 的 `定时与网络 -> 默认代理` 配置. 单个账号也可展开 `账号代理`, 选择沿用上级、直连、默认代理或指定代理. 支持 HTTP、HTTPS 和 SOCKS5, 包括 `socks5://用户名:密码@主机:1080`. 使用 SOCKS5 认证时, 用户名和密码均需填写, URL 解码后各为 1 至 255 个 UTF-8 字节; 无认证 SOCKS5 仍可使用. 特殊字符应进行百分号编码, 例如用户名 `user@example`、密码 `pass:word@` 可写为 `socks5://user%40example:pass%3Aword%40@proxy.example:1080`. URL 和其中的凭据加密保存, 已保存值不会回显. 代理认证失败会显示明确错误, 不会自动改为直连. 登录、acw 验证及签到沿用同一代理会话. 该设置用于站点请求, 通知渠道的网络设置保持现有行为.

通知渠道包含 Fy1Push、邮件、Telegram、Bark、Gotify、PushPlus、Server 酱、钉钉、飞书和企业微信. Fy1Push 使用 HTTPS 地址与发送 token, token 不写日志. `accepted` 只表示服务端接收, 不保证手机送达. 相同待处理结果不反复通知; 配置变化、状态变化或通知失败可触发后续发送. 可配置 WebUI 地址, 通知中的链接只携带账号 ID, 不包含密码、Cookie 或 token. WebUI 仍需管理密码登录. 私有 SSH 转发场景按实际转发地址打开.

## 数据与旧配置迁移

配置、HTTP 会话均通过独立用途的 AES-GCM 加密保存于 SQLite. 管理密码只保存加盐哈希. 执行记录和暂停原因不是全部加密, 整个数据目录仍应私有保存. 输入框隐藏已保存秘密, 留空保留, 点击清除才删除. 修改凭据使旧 HTTP 会话绑定失效, 不会误复用其他账号的会话.

旧版配置在取得服务独占锁后迁移: 先在同一数据库事务内归档原始密文与版本, 再生成 schema 2 配置, 关闭旧定时任务. 支持转换的 Any Cookie/密码账号保留; OAuth、Agent 缺令牌等账号转换为禁用待配置. 不支持的自定义站点仅从活动配置中移除, 原始内容保留在加密归档. 旧浏览器加密快照和历史记录不删除, 新执行器不读取或跨平台导入它们. 不会自动清空所有已保存数据.

迁移会增加配置版本. 若需要回退, 在首次启动新版本前停止服务, 备份整个数据目录与独立 master.key. 数据和密钥分开保管, 不更换密钥来重置已有数据. 本版本尚无图形化归档恢复或主密钥轮换入口.

## 启动配置

| 环境变量 | 默认值/说明 |
|---|---|
| CHECKIN_WEB_HOST | 127.0.0.1, 容器内部可为 0.0.0.0 |
| CHECKIN_WEB_PORT | 8765 |
| CHECKIN_WEB_DATA_DIR | server-data |
| CHECKIN_WEB_KEY_FILE | server-keys/master.key, 原始 32 字节 |
| CHECKIN_WEB_PASSWORD_FILE | 首次管理密码的只读文本文件, 至少 16 字符 |
| CHECKIN_WEB_PASSWORD | 首次密码的备选进程环境来源, 优先使用密码文件 |

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

然后通过 http://127.0.0.1:18765 管理. 本机端口被占用时可更换转发左侧端口. 不直接公开明文 WebUI. 默认服务只接受 loopback Host, 公网 HTTPS 暴露和认证模型不在本次实现范围内.

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
