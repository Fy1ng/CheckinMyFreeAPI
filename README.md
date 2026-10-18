# Any Router 多账号自动签到

[![GitHub Actions](https://github.com/millylee/anyrouter-check-in/workflows/PR%20Quality%20Checks/badge.svg)](https://github.com/millylee/anyrouter-check-in/actions)
[![codecov](https://codecov.io/gh/millylee/anyrouter-check-in/branch/main/graph/badge.svg)](https://codecov.io/gh/millylee/anyrouter-check-in)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/millylee/anyrouter-check-in/main.svg)](https://results.pre-commit.ci/latest/github/millylee/anyrouter-check-in/main)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/Code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![License](https://img.shields.io/github/license/millylee/anyrouter-check-in)](LICENSE)

多平台多账号自动签到, 内置 Any Router 与 Agent Router. 其他 NewAPI/OneAPI 站点需要核对接口和登录能力后配置.

## 功能特性

- 多平台、多账号签到和可选通知.
- 站点邮箱密码登录, 以及 LinuxDo/GitHub OAuth 登录.
- 同一 OAuth 身份复用浏览器身份状态, 各站点账号独立校验绑定.
- 登录失效时, 在本次 GitHub Actions 运行内通过受密码保护的临时浏览器完成登录、验证码与授权.
- 经账号校验的浏览器状态使用 AES-256-GCM 加密后缓存, 不缓存明文 profile, 不上传登录截图.

本实现不自动处理第三方账号密码、验证码或 MFA, 不要求从本机导出 Cookie、浏览器 profile 或 JSON 登录态. 遇到访问封锁或限流会报错, 不通过轮换代理反复尝试.

## 使用方法

### 1. Fork 并设置运行环境

1. Fork 本仓库, 在 Actions 中启用 `AnyRouter 自动签到` workflow.
2. 在 Settings -> Environments 创建 `production` 环境.
3. 在该环境的 Environment secrets 中配置下面的密钥与账号数据.
4. 建议将 `production` 的 Deployment branches and tags 限制为仓库默认分支.

workflow 只接受 `schedule` 和 `workflow_dispatch`, 且只在仓库默认分支执行. 手动运行时请选择默认分支; 其他分支会跳过签到 job. 不要将生产密钥配置到 PR 测试任务.

### 2. 配置加密密钥与人工接管密码

| Environment secret | 用途 |
| --- | --- |
| `CHECKIN_STATE_KEY` | 必填. base64 编码的随机 32 字节 AES 密钥, 用于解密和加密跨运行登录态. |
| `CHECKIN_REMOTE_PASSWORD` | 首次登录或重新登录需要人工接管时必填. 独立的 24-512 字符远程接管密码. |
| `CHECKIN_IDENTITIES` | 使用 OAuth 时必填. 身份映射及其代理策略; 无 OAuth 账号时可省略或填写 `{}`. |
| `ANYROUTER_ACCOUNTS` | 必填. 需要签到的站点账号 JSON 数组. |
| `PROVIDERS` | 可选. 自定义站点配置或覆盖内置配置. |

在可信的本机终端运行以下命令生成 `CHECKIN_STATE_KEY`, 将输出直接保存到对应 Environment secret. 此处只是生成方法, 示例文档不包含可用密钥:

```bash
python -c "import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

`CHECKIN_REMOTE_PASSWORD` 应独立生成并保存到密码管理器. 例如:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

不要复用 GitHub/LinuxDo/站点账号密码, 不要将密钥或接管密码放入通知、运行日志、URL、仓库文件或在线配置生成器. 登录窗口只通知临时 HTTPS 地址, 打开后再输入预先保存的接管密码.

### 3. 关联 Provider、Identity 与 Account

三者职责不同:

- **Provider**: 签到站点的 HTTPS origin、接口路径、OAuth client 配置与默认代理策略. 内置 `anyrouter` 和 `agentrouter`.
- **Identity**: 一个 LinuxDo 或 GitHub 第三方身份. 相同别名复用该身份的浏览器 profile, 不存第三方密码.
- **Account**: 某个 Provider 下需要签到的站点账号. 使用 `auth.identity` 关联 Identity, 用 `api_user` 或 `expected_username` 校验站点返回的实际账号.

例如, 同一 LinuxDo 身份关联两个站点时, 将下面的 JSON 对象填入 `CHECKIN_IDENTITIES`:

```json
{
  "linuxdo-main": {
    "type": "linuxdo",
    "proxy": "direct"
  }
}
```

将下面的 JSON 数组填入 `ANYROUTER_ACCOUNTS`. `expected_username` 必须换成各目标站点自己的用户名, 不要直接假定等于 LinuxDo 昵称:

```json
[
  {
    "id": "anyrouter-main",
    "name": "AnyRouter 主账号",
    "provider": "anyrouter",
    "auth": {"type": "linuxdo", "identity": "linuxdo-main"},
    "expected_username": "your_anyrouter_username"
  },
  {
    "id": "agentrouter-main",
    "name": "AgentRouter 主账号",
    "provider": "agentrouter",
    "auth": {"type": "linuxdo", "identity": "linuxdo-main"},
    "expected_username": "your_agentrouter_username"
  }
]
```

示例明确使用 `direct`, 因此两个站点与 LinuxDo 都直连. 如果需要代理, 将该 Identity 的 `proxy` 改为 `default`, 并配置下面的 `CHECKIN_PROXY_URL` 或订阅代理. 不要为两个站点选择不同出口后仍复用同一个 Identity.

GitHub Identity 的格式相同: `CHECKIN_IDENTITIES` 中使用 `"type":"github"`, Account 的 `auth.type` 也使用 `github`, `auth.identity` 填对应别名. 第三方平台必须是该站点实际支持的登录方式; 配置一个 Identity 不会使站点自动支持它.

**Account 字段**:

| 字段 | 说明 |
| --- | --- |
| `id` | 建议显式填写稳定且唯一的字符串. 不填时按 Provider 与显示名称生成状态标识, 改名会影响状态复用. |
| `name` | 可选, 用于日志和通知, 不填为 `Account 1` 等. 不要填写密码或其他秘密. |
| `provider` | 可选, 默认为 `anyrouter`. |
| `auth` | OAuth 配置, 必须含 `type` (`linuxdo`/`github`) 与 `identity` (已配置的 Identity 别名). |
| `api_user` | 目标站点的用户 ID, 建议用字符串. OAuth 至少配置它或 `expected_username` 之一. |
| `expected_username` | 目标站点精确用户名. 与 `api_user` 同时填写时两者都必须匹配. |
| `proxy` | 可选, 支持 `direct`、`default` 或代理 URL. OAuth 推荐统一配置在 Identity 上. |
| `email` + `password` | 站点自身的邮箱/用户名与密码登录, 与 OAuth 互斥. |
| `cookies` | 兼容旧配置的 Cookie 对象或 Cookie 字符串, 不需要为 OAuth 提供. |

Identity 的 `type` 必须与 Account 的 `auth.type` 相同. 一个 Account 不得混合 OAuth 与 `email`、`password`、`cookies`. 身份或账号不匹配会停止该账号的处理, 不会把新登录结果默认为目标账号.

### 4. 在本次运行中完成首次登录

1. 在 Actions -> `AnyRouter 自动签到` -> Run workflow, 选择默认分支运行.
2. 程序先尝试所有账号的缓存与自动登录, 再依次处理需要人工登录的账号.
3. 需要接管时, 查看本次运行日志中的 `[MANUAL] Protected temporary browser` 地址. 已配置通知时也会发送地址, 通知失败时仍可从日志打开.
4. 用浏览器打开临时 HTTPS 地址, 输入 `CHECKIN_REMOTE_PASSWORD`, 在远程 Runner 浏览器中完成对应第三方或站点登录、验证码和 MFA.
5. 如登录后没有返回授权流程, 点击 `已完成登录, 继续授权` 对应的界面按钮, 再在远程浏览器内完成授权.
6. 程序验证回调、OAuth state 与实际站点账号, 继续签到并保存加密快照. 完成、超时或任务终止后入口关闭.

当前 workflow 设置每次接管最多 `600` 秒, 全部接管累计预算 `1800` 秒, job 最长 `90` 分钟. 第三方同一 Identity 接管失败后, 本轮后续依赖该身份的人工重试会失败, 避免重复等待. 已有其他账号仍会按批次流程处理. 超时后需重新运行, 不能使用旧通知地址续接上一次 Runner.

**可用性限制**: 远程接管只支持有界面的 Linux/Xvfb 环境, 需要 `x11vnc`、noVNC 和 `cloudflared`. 当前 workflow 安装这些依赖, 按需启动只监听 loopback 的 VNC/网关与临时 Cloudflare HTTPS 隧道. 临时隧道、Runner 出网、目标站点或第三方平台不可用时, 入口可能无法创建或登录无法完成. 本机 Windows 的普通运行不提供此接管入口. 不保证 GitHub Runner 的 IP 被目标站点或第三方平台接受.

### 5. 后续运行与执行时间

- workflow 每 6 小时触发一次 (`0 */6 * * *`, UTC), GitHub 定时任务可能延迟.
- 已验证的登录态有效时自动复用, 过期且需要用户操作时再次开启短时接管.
- 默认只有失败或余额发生变化才发送签到结果通知; 人工接管通知独立发送.
- 任一账号失败时进程返回非零状态, 即使其他账号成功, workflow 仍显示失败.

## 加密缓存与轮换

安全模式的明文工作目录默认是 `.auth-state/`, 加密输出为 `.auth-cache/auth-state.enc`, 上一份有效密文为 `.auth-cache/auth-state.previous.enc`. 只在站点账号身份核对通过后提交 profile 和账号记录. workflow 只保存 `.auth-cache/*.enc`, 不上传明文 profile、Cookie JSON、截图或浏览器日志作为 artifact. 退出时及 workflow 的清理步骤清除明文状态.

快照绑定仓库名、操作系统、CloakBrowser 与 Chromium 兼容版本. 缓存 key 还包含 `uv.lock` 的哈希和仓库/环境 Variable `CHECKIN_STATE_EPOCH` (默认 `1`). 错误密钥、损坏或不兼容的现有快照会报错并拒绝覆盖; 有效的上一份快照可用于恢复. 不要用关闭身份校验或回退到明文缓存解决恢复失败.

需要主动清空登录态、切换密钥或进行不兼容升级时:

1. 等待当前签到运行结束, 避免旧运行继续写缓存.
2. 如需密钥轮换, 生成新的 `CHECKIN_STATE_KEY` 并更新 `production` Environment secret.
3. 在 `production` Environment variables 中新增或递增 `CHECKIN_STATE_EPOCH`, 例如从 `1` 改为 `2`, 使后续运行不恢复旧密钥对应的缓存.
4. 重新运行, 完成人工登录, 生成新加密快照. 需要时在仓库 Actions caches 中删除旧 `auth-v1-` 缓存.

`CHECKIN_STATE_EPOCH` 只隔离 GitHub Actions 缓存命名, 不会撤销站点会话. 怀疑泄露时还需在相关站点/Identity 平台撤销会话并更换接管密码. 本地轮换还需先隔离或删除 `.auth-cache/` 中旧的两个 `.enc` 文件, 单改 epoch 不影响本地读取路径. 不要提交或公开密文与密钥; 缓存恢复会受 GitHub 保留策略影响, 不能保证永久保存登录.

## 自定义 Provider 配置

`PROVIDERS` 是 JSON 对象, 自定义配置会覆盖同名内置项, 未填写的可选字段继承内置值. 每个自定义条目仍必须包含 `domain`, 且安全模式要求其为纯 HTTPS origin (不含路径、账号密码或查询参数).

```json
{
  "customrouter": {
    "domain": "https://custom.example.com",
    "login_path": "/login",
    "sign_in_path": "/api/user/sign_in",
    "user_info_path": "/api/user/self",
    "api_user_key": "new-api-user",
    "status_path": "/api/status",
    "auth_state_path": "/api/oauth/state",
    "use_proxy": false
  }
}
```

| 字段 | 默认值及用途 |
| --- | --- |
| `domain` | 必填, 站点 HTTPS origin. |
| `login_path` | `/login`, 浏览器进入页面. |
| `sign_in_path` | `/api/user/sign_in`, `null` 表示由查询用户信息完成签到. |
| `user_info_path` | `/api/user/self`, 用于会话与账号核验. |
| `api_user_key` | `new-api-user`, 用户标识请求头名. |
| `status_path` | `/api/status`, 获取站点 OAuth client 配置. |
| `auth_state_path` | `/api/oauth/state`, 获取站点生成的 OAuth state. |
| `oauth_client_ids` | 可选对象, 如 `{"linuxdo":"site_registered_client_id"}`, 覆盖 `/api/status` 返回的相应 client ID. 必须使用目标站点实际注册的值. |
| `use_proxy` | 新站点默认 `false`, 决定未显式指定代理时是否使用 `CHECKIN_PROXY_URL`. |
| `persist_profile` | 旧登录流程的 profile 持久化设置; 安全模式通过加密快照管理 profile. |
| `bypass_method`、`waf_cookie_names` | 兼容旧流程的 WAF Cookie 获取配置. 安全模式在同一浏览器上下文执行登录与请求, 这些字段不代表可自动绕过验证码或封锁. |

内置 `anyrouter` 为显式签到接口、默认直连; `agentrouter` 的 `sign_in_path` 为 `null`, 默认要求代理. OAuth 授权支持 LinuxDo/GitHub 的标准站点回调路径 `/oauth/<type>` 与 `/api/oauth/<type>`. 自定义 API、回调协议或不同站点实现不保证兼容, 应先验证再使用真实账号.

## 代理配置

代理策略支持:

- `direct`: 显式直连, 覆盖 Provider 的 `use_proxy`.
- `default`: 使用 `CHECKIN_PROXY_URL`, 未配置时立即报错.
- 代理 URL: `http://host:port`、`https://host:port` 或不带认证的 `socks5://host:port`. HTTP(S) 可以带代理认证, 不支持带查询参数、fragment 或非根路径的地址.
- 省略: 按 Provider 的 `use_proxy` 决定是否使用 `CHECKIN_PROXY_URL`.

同一 Identity 在多个 Account 下解析出的最终代理必须完全一致, 包括使用 `direct` 或默认代理的结果. Identity 指定了代理时, Account 若也指定代理, 两者必须一致, 否则拒绝启动. 为共享 Identity 显式指定 `direct` 或 `default` 可避免内置 Provider 默认值不同造成冲突. Provider 请求、OAuth 和人工接管中的浏览器访问都使用同一 profile 的网络策略. 程序核对的是代理配置 URL, 不能证明公网出口 IP 固定; 当前 Mihomo 订阅使用 `url-test` 选路, 上游节点可能切换. 共享 Identity 需要固定出口时, 应提供可保证固定出口的现有代理, 不要把相同代理 URL 当作相同出口的证明.

GitHub Actions 的 `production` Environment secrets 可配置:

- `CHECKIN_PROXY_URL`: 使用现有代理. 对 GitHub 托管 Runner, 地址必须能从该 Runner 访问; 本机的 `127.0.0.1` 不是 Runner 上的服务.
- `PROXY_SUBSCRIPTION_URL`: 可选 Clash/Mihomo 订阅. `scripts/setup_mihomo_proxy.sh` 在 Runner 上启动本地代理并提供 `CHECKIN_PROXY_URL`. 已设置前者时优先使用现有代理.

workflow 指定 Mihomo 版本, 下载后校验固定 SHA256. 若自行更改版本, 必须同时提供该压缩包可信的 `MIHOMO_SHA256`. 默认通过 `https://www.google.com/generate_204` 测试连通性, 脚本可用 `PROXY_TEST_URL` 覆盖. 连通性检查不等于目标站点登录成功. 代理缺失或失败时不会静默改为直连; 不要通过更换代理绕过站点访问限制.

## 兼容已有站点密码或 Cookie 配置

站点邮箱密码登录可以继续使用, 同样受 workflow 的加密状态管理:

```json
[
  {
    "id": "site-password-main",
    "name": "站点账号",
    "provider": "anyrouter",
    "email": "account@example.com",
    "password": "replace_with_site_password"
  }
]
```

已有 Cookie 配置仍兼容 `{"cookies":{"session":"existing_session"},"api_user":"12345"}`. 不建议为新配置导出 Cookie. 站点密码流程可省略 `api_user`, Cookie 流程必须提供; OAuth 至少提供 `api_user` 或 `expected_username`. Cookie/密码不能与 OAuth 混用. 不要把第三方 LinuxDo/GitHub 密码填入站点的 `email`、`password` 字段.

## 开启通知

在 `production` Environment secrets 中添加所需项, 每种通知渠道独立配置. 人工接管通知只包含本次入口、账号显示名与有效时间, 不包含接管密码或 Cookie. 地址在接管开始后才发送, 需要及时打开; 无通知渠道时查看运行日志.

| 渠道 | 环境变量 |
| --- | --- |
| SMTP 邮件 | `EMAIL_USER`, `EMAIL_PASS`, `EMAIL_TO`; 可选 `EMAIL_SENDER` (默认 `EMAIL_USER`)、`CUSTOM_SMTP_SERVER`. |
| 钉钉 | `DINGDING_WEBHOOK`, 有关键词要求时可设置 `AnyRouter`. |
| 飞书 | `FEISHU_WEBHOOK`. |
| 企业微信 | `WEIXIN_WEBHOOK`. |
| PushPlus | `PUSHPLUS_TOKEN`. |
| Server 酱 | `SERVERPUSHKEY`. |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`. |
| Gotify | `GOTIFY_URL`, `GOTIFY_TOKEN`; 可选 `GOTIFY_PRIORITY` (1-10, 默认 9). |
| Bark | `BARK_KEY`; 可选 `BARK_SERVER` (默认 `https://api.day.app`). |

通知服务可能失败或延迟, 不能用收到通知作为登录、签到或缓存保存成功的依据. 以本次 Actions 日志和站点实际结果为准.

## 故障排除

- `OAUTH_IDENTITY_NOT_CONFIGURED`: 检查 Identity 别名、`type` 及 Account 的 `auth` 关联.
- `ACCOUNT_IDENTITY_PROXY_CONFLICT` / `SHARED_IDENTITY_PROXY_CONFLICT`: 为该 Identity 统一代理, 不要依赖不同 Provider 的隐含默认值.
- `ACCOUNT_MISMATCH`: 检查站点 `api_user` / `expected_username`, 在远程浏览器确认所登录的实际身份. 不要通过删除校验字段接受未知账号.
- `MANUAL_LOGIN_UNAVAILABLE_OR_TIMED_OUT`: 检查接管密码长度、同次入口时限、Linux/Xvfb 依赖与临时隧道连通性, 然后重新运行.
- `No valid compatible encrypted snapshot`: 保留现有缓存作排查, 按上文同步处理密钥与 epoch, 重新登录. 不要把密文发到公开 issue.
- `RATE_LIMITED` / `ACCESS_BLOCKED` / `NETWORK_OR_SERVICE_ERROR`: 检查站点状态或等待限制解除. 不自动切换代理重试.
- 401/会话过期: 有效配置下会重新走登录恢复; 旧 Cookie 可能提前失效, 不承诺固定有效期.
- HTTP 200 但签到失败: 查看站点业务返回, 可能是接口或数据库故障; HTTP 状态码不等于业务成功.

安全模式强制关闭 `DEBUG_MODE` 的详细调试与截图, 不通过开启调试输出登录页面、OAuth URL 或凭据进行排查.

## 本地开发与验证

```bash
uv sync --frozen --dev
uv run --frozen python -m cloakbrowser install

# 复制 .env.example 为本地 .env, 按说明替换占位符.
# JSON 环境变量使用单行, 不要把真实 .env 加入 Git.
# 配置密钥后可运行真实签到, 会访问站点并可能发送已配置通知:
uv run --frozen checkin.py
```

有本地浏览器时可设置 `CLOAKBROWSER_BINARY_PATH=/path/to/browser`. 本地普通运行默认 headless, 不包含 GitHub Actions 的 Xvfb/远程接管基础设施. `CHECKIN_SECURE_MODE=true` 关闭敏感调试产物, 安全认证运行时由 `CHECKIN_STATE_KEY` 或 OAuth 账号配置启用; 只设置该布尔开关不能替代密钥.

本地可用的接管参数是 `CHECKIN_MANUAL_LOGIN` (默认关闭)、`CHECKIN_HEADLESS` (默认 `true`)、`CHECKIN_MANUAL_TIMEOUT_SECONDS` (默认 `600`, 范围 30-1800)、`CHECKIN_MANUAL_TOTAL_TIMEOUT_SECONDS` (默认 `1800`, 范围 30-3600). 实际接管仍要求 Linux、有效 `DISPLAY` 与全部依赖. 当前 workflow 已固定这些参数, 修改本地 `.env` 不会改变远端 workflow.

```bash
# 自动化检查与本地模拟测试, 不使用真实账号和通知密钥
uv run --frozen pytest tests/
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy .
uv run --frozen bandit -r . -c pyproject.toml

# 可选覆盖率
uv run --frozen pytest tests/ --cov=. --cov-report=html
```

新增认证测试覆盖模拟 OAuth 回调、身份与代理约束、加密快照及临时接管网关. 本地模拟验证不等于真实 GitHub Runner、临时 Cloudflare 隧道、LinuxDo/GitHub 登录或目标站点签到验收. 当前安全 OAuth/人工接管功能尚未完成这些真实环境验收, 使用前需在自己的默认分支和 `production` 环境核对结果.

## 贡献指南

提交 Pull Request 前请阅读 [贡献指南](CONTRIBUTING.md). 项目使用 Ruff、MyPy、Bandit、Pytest 和 pre-commit, PR workflow 执行相应质量检查与覆盖率报告.

```bash
uv sync --frozen --dev
uv run --frozen pre-commit install
```

## 免责声明

本脚本用于学习和研究, 使用前请遵守相关网站的使用条款, 仅操作自己的账号或已获授权的账号.
