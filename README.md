# Any Router 多账号签到 WebUI

本地或自有 Linux 服务器运行的多账号签到服务, 内置 AnyRouter 与 AgentRouter, 支持站点密码、LinuxDo/GitHub OAuth 和兼容已有 Cookie 配置. 账号、站点、身份、代理、通知与定时任务通过浏览器表单管理.

运行架构为 Python 3.11 + aiohttp + SQLite. 配置中的敏感值与已验证登录态使用独立主密钥加密, WebUI 密码只保存哈希. Linux Docker Compose 提供同一 WebUI 内的限时浏览器人工接管, 用于登录、验证码和 MFA. 不自动处理第三方平台密码或验证码, 不通过更换代理规避访问限制.

GitHub Actions 只运行代码检查和模拟测试, 不运行真实账号签到. 当前版本尚未部署到服务器; Docker 构建、Linux 浏览器接管和真实网站登录需要在相应环境另行验收. 本地模拟检查通过不能证明目标站点接受自动签到或服务器出口 IP, 使用前应核对站点条款.

## 本地启动

安装 Python 3.11+ 和 [uv](https://docs.astral.sh/uv/getting-started/installation/), 在仓库目录运行:

```bash
uv sync --frozen --dev
uv run --frozen python -m server
```

打开 `http://127.0.0.1:8765`. 首次交互式启动会在终端通过隐藏输入设置 WebUI 密码, 至少 16 字符. 推荐使用密码管理器生成的长密码. 密码不会放进 URL 或访问日志. 非交互启动应显式提供 `CHECKIN_WEB_PASSWORD_FILE` 指向密码文件; 也支持 `CHECKIN_WEB_PASSWORD`, 不建议写入命令历史或普通配置文件.

本地默认数据目录为 `./server-data`, SQLite 文件为 `server-data/webui.sqlite3`. 主密钥是 `./server-keys/master.key` 中的原始 32 字节, 本地首次启动可自动生成. `server-data` 与 `server-keys` 都不得提交到 Git. WebUI 日常启动不会读取 `.env`, 也不会自动导入旧账号或发起真实签到.

Windows 可管理配置、查看状态和调度任务. 执行签到需安装 CloakBrowser:

```bash
uv run --frozen python -m cloakbrowser install
```

Windows 下可选择 headless 浏览器处理仍有效的登录态, 人工浏览器接管需要 Linux + DISPLAY/Xvfb, 页面会显示该能力是否可用. headless 模式不能人工接管. 不要把 Windows 本地界面验收当作 Linux 浏览器接管验收.

## 浏览器配置和运行

1. 登录 WebUI, 在表单中维护站点 Provider、OAuth 身份 Identity 与目标账号 Account.
2. 设置目标站点的 `api_user` 或 `expected_username`, 保存配置. OAuth 至少提供其中一项, 同时填写时两项都必须匹配.
3. 按需填写现有代理、通知渠道和浏览器参数, 保存后再点击手动运行.
4. 需要人工登录时, 在本次任务的 WebUI 接管入口完成登录、验证码和授权. 入口依赖当前登录会话, 只在任务需要且未超时时可用, 不会启动 Cloudflare 公网隧道.
5. 确认手动运行结果后再启用定时任务. 调度默认关闭, 默认间隔为 360 分钟.

保存配置与执行签到是独立操作. 同一服务只允许一个任务运行, 同一 OAuth 身份的浏览器处理串行执行. 运行中的配置使用该次任务的快照, 后续保存供下一次运行使用. 可以取消当前任务, 取消后不会为该任务自动重试; 定时调度在仍启用时可产生后续独立任务. 人工接管超时后入口关闭, 需要下一次任务重新建立.

不要同时启动多个服务实例共用同一数据目录. 定时任务需要服务进程持续运行, 不补跑停机期间的每次计划. 站点限流、封锁、账号不匹配或登录失败会显示失败结果, 不轮换出口反复尝试.

## Linux Docker Compose

此部分准备可部署配置, 不会在本地自动部署. 需要 Docker Engine 和 Compose v2. 镜像使用 Python 3.11, `uv.lock` 锁定依赖, 构建时安装对应 CloakBrowser 与 Chromium 系统依赖、Xvfb、x11vnc 和 noVNC. 构建过程需要访问依赖和浏览器下载源.

先在 Linux 仓库目录生成独立密钥与 WebUI 密码文件. 以下操作只生成本机秘密, 不打印内容; 生成时不得覆盖已有密钥:

```bash
mkdir -p server-keys
chmod 700 server-keys
python3 - <<'PY'
import getpass
import os
import secrets
from pathlib import Path

key = Path('server-keys/master.key')
password_file = Path('server-keys/web-password')
if key.exists() or password_file.exists():
    raise SystemExit('Key or password file already exists; preserve it instead of overwriting.')
password = getpass.getpass('WebUI password (at least 16 characters): ')
if len(password) < 16 or password != getpass.getpass('Confirm WebUI password: '):
    raise SystemExit('Password too short or confirmation does not match.')
for path, value in ((key, secrets.token_bytes(32)), (password_file, password.encode('utf-8'))):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(value)
PY
sudo chown 10001:10001 server-keys/master.key server-keys/web-password

docker compose up --build -d
```

容器使用固定非 root UID/GID `10001:10001`. Linux 主机上的只读密钥和密码文件必须允许该 UID 读取. `compose.yaml` 不会自动创建缺失的秘密文件, 缺失时应先准备文件. Docker Desktop 的宿主文件权限映射与 Linux 不同, 仍需检查挂载结果.

Compose 配置:

| 项目 | 设置 |
| --- | --- |
| 宿主访问地址 | `127.0.0.1:8765`, 只允许宿主本机访问. |
| 容器内监听 | `0.0.0.0:8765`, 仅用于 Docker 端口映射. |
| 持久化数据 | 命名卷 `checkin-data` 挂载 `/data`. |
| 独立密钥 | `server-keys/master.key` 只读挂载 `/keys/master.key`. |
| 首次密码来源 | `server-keys/web-password` 只读挂载 `/run/secrets/web-password`. |
| 明文认证工作目录 | `/tmp/checkin-auth` 使用限额 512 MiB 的 tmpfs. |
| 浏览器共享内存 | `shm_size: 1gb`. |
| 子进程管理 | `init: true`, 启动脚本按需使用 Xvfb. |
| 接管访问 | noVNC 通过同一 WebUI 认证入口代理, 不发布 VNC 端口. |

本机使用 `http://127.0.0.1:8765`. 查看状态可运行 `docker compose ps`, 停止使用 `docker compose down`. 普通 `down` 保留命名数据卷; 不要使用 `down -v` 删除需要的配置和登录态. WebUI 初始密码文件是引导输入, 后续密码校验依据数据库中的哈希; 不要假定修改该文件会重置已存在的 WebUI 密码.

服务器访问推荐 SSH 本地转发, 例如在自己的电脑执行:

```bash
ssh -N -L 8765:127.0.0.1:8765 your-server
```

保持 SSH 会话, 在本机浏览器访问 `http://127.0.0.1:8765`. 若本机端口被占用, 可将命令左侧端口改为 `18765`, 然后访问 `http://127.0.0.1:18765`. 不要直接把明文 HTTP WebUI 或 VNC 发布到公网; 需要公网访问时应另行配置 HTTPS 和访问控制.

## Provider、Identity 与 Account

- Provider 是目标站点的纯 HTTPS origin、接口路径、OAuth client 配置和默认代理策略. 内置 `anyrouter` 与 `agentrouter`.
- Identity 是 LinuxDo/GitHub 第三方身份别名, 多个目标站点可关联同一身份, 不保存第三方平台密码.
- Account 是需要签到的目标站点账号, 关联 Provider 和可选 Identity, 使用站点返回的用户信息核对绑定.

共享身份示例:

```json
{
  "linuxdo-main": {"type": "linuxdo", "proxy": "direct"}
}
```

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

表单填写对应字段即可, 无需手写 JSON. 上述 JSON 仅用于说明关联关系和兼容旧配置. `expected_username` 是目标站点自己的用户名, 不要假定等于第三方昵称. GitHub OAuth 将 Identity 的 `type` 与 Account 的 `auth.type` 同时设为 `github`. 目标站点本身必须支持对应 OAuth 平台.

Account 的 `id` 应唯一且稳定, 修改它会影响登录态复用. OAuth 不能与 `email`、`password`、`cookies` 混用. 站点密码方式只填写目标站点凭据, 不要填写 LinuxDo/GitHub 密码. 已有 Cookie 方式继续兼容, 必须设置 `api_user`, 新 OAuth 配置无需导出 Cookie.

自定义 Provider 至少填写 `domain`, 即使只是覆盖内置站点. `domain` 只接受纯 HTTPS origin, 不含路径、用户密码或查询参数. 可配置字段:

| 字段 | 默认值或用途 |
| --- | --- |
| `login_path` | `/login`, 浏览器登录页面. |
| `sign_in_path` | `/api/user/sign_in`, `null` 表示查询用户信息完成签到. |
| `user_info_path` | `/api/user/self`, 会话与账号核验. |
| `api_user_key` | `new-api-user`, 用户 ID 请求头名. |
| `status_path` | `/api/status`, 读取站点 OAuth client 配置. |
| `auth_state_path` | `/api/oauth/state`, 读取站点 OAuth state. |
| `oauth_client_ids` | 可覆盖 `linuxdo`/`github` client ID, 必须使用该站点实际注册的值. |
| `use_proxy` | 未显式指定代理时是否使用默认代理. |

内置 AnyRouter 默认直连, AgentRouter 默认要求代理. 为共享 Identity 显式选择 `direct` 或 `default` 可以避免两者默认值不同. OAuth 支持标准站点回调路径 `/oauth/<type>` 和 `/api/oauth/<type>`, 自定义站点仍需核对实际接口.

## 代理与通知

代理支持 `direct`、`default` 或代理 URL. `default` 使用配置中的默认代理, 缺失时失败, 不静默直连. HTTP(S) 代理可带认证, SOCKS5 代理当前不支持认证. 同一 Identity 关联账号的最终代理配置必须完全一致. 相同代理 URL 不能保证上游公网出口固定, 需要稳定出口时应使用可保证固定出口的现有代理.

WebUI 不会启动 Mihomo 或自动消费订阅. 原有 `scripts/setup_mihomo_proxy.sh` 作为独立 CLI 兼容工具保留, 订阅和代理服务由使用者管理. 容器中的 `127.0.0.1` 指容器自身, 不代表宿主机已有代理.

通知在 WebUI 中按需配置, 支持 SMTP、钉钉、飞书、企业微信、PushPlus、Server 酱、Telegram、Gotify 和 Bark. 保存秘密后界面使用掩码, 编辑时按表单说明保留或清除旧值. 通知密码、Webhook token、代理密码和站点凭据不应出现在 URL、运行记录或截图中. 通知失败或延迟不代表任务失败或成功, 以任务记录和站点实际结果为准.

## 数据备份与恢复

配置和执行记录存放在 SQLite 中, 敏感配置与登录态加密. SQLite 中的元数据与运行状态并非全部加密, 整个数据目录仍应按私有数据保护. 明文浏览器 profile 只作为本次任务工作目录, 正常清理时删除; Compose 使用 tmpfs 避免把这部分写进持久卷.

备份应同时保留数据目录或命名卷, 以及独立保存的 `master.key`. 先停止服务再复制, 避免复制到一半写入的 SQLite 文件或认证快照. 密钥与备份应分开保存, 遗失密钥无法解密既有敏感配置与登录态. 不要直接更换主密钥文件, 否则已有数据将无法读取; 当前版本没有自动密钥轮换迁移命令.

加密登录态只在实际站点账号校验通过后保存, 并保留上一份有效快照供恢复. 错误密钥、损坏或浏览器版本不兼容的快照会报错并拒绝覆盖. 恢复失败时先备份并保留旧数据, 不要关闭身份校验或改用明文缓存. 不同操作系统或不兼容浏览器版本之间不保证登录态可迁移, 必要时重新登录.

若怀疑泄露, 应在相关站点与 OAuth 身份平台撤销会话, 再按备份和重新登录流程处理. 只删除本地缓存不会撤销服务器端会话. 密文与密钥都不应放到公开 issue 或日志中.

## 导入已有配置与 CLI 兼容

服务器不会隐式读取 `.env`. 可在首次配置时显式一次性导入:

```bash
uv run --frozen python -m server --import-env .env
```

导入用于将旧账号、Identity、Provider、代理、通知和浏览器配置迁移到数据库. 在 WebUI 中检查后手动运行, 不要把包含真实秘密的 `.env` 提交到 Git. 首次 WebUI 密码与原 `CHECKIN_REMOTE_PASSWORD` 是不同用途, 旧 CLI 的 base64 `CHECKIN_STATE_KEY` 也不同于 WebUI 的原始 32 字节主密钥文件. 原 Actions 缓存没有自动迁移保证, 应保留备份, 必要时重新登录.

旧命令仍保留:

```bash
# 复制 .env.example 为 .env, 按需填写真实的 CLI 配置.
# 此命令会访问配置站点, 并可能发送已启用的通知.
uv run --frozen checkin.py
```

CLI 的变量格式见 [.env.example](.env.example). CLI 不会读取 WebUI 数据库, 不要与 WebUI 同时使用同一明文认证工作目录或缓存. 服务器启动变量如下, 需由进程环境显式提供:

| 变量 | 默认值或说明 |
| --- | --- |
| `CHECKIN_WEB_HOST` | `127.0.0.1`. Compose 内部显式改为 `0.0.0.0`. |
| `CHECKIN_WEB_PORT` | `8765`. |
| `CHECKIN_WEB_DATA_DIR` | `./server-data`. |
| `CHECKIN_WEB_KEY_FILE` | `./server-keys/master.key`, 原始 32 字节文件. |
| `CHECKIN_WEB_PASSWORD_FILE` | 可选, 首次密码的只读文件路径. |
| `CHECKIN_WEB_PASSWORD` | 可选首次密码, 优先使用文件来源. |
| `CHECKIN_AUTH_ROOT` | 临时明文认证目录, Compose 为 `/tmp/checkin-auth`. |
| `CHECKIN_WEB_XVFB` | `scripts/start_server.sh` 专用, 默认 `true`, 可设 `false` 跳过 Xvfb. |

Linux 原生运行且已安装 Xvfb/x11vnc/noVNC 时, 可用 `sh scripts/start_server.sh` 包装启动. 已有 `DISPLAY` 时脚本复用它, 否则创建禁用 TCP 监听的虚拟显示. 服务的人工接管能力还取决于本次任务的浏览器配置和系统依赖.

## 开发检查

```bash
uv sync --frozen --dev
uv run --frozen pytest tests/
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy .
uv run --frozen bandit -r . -c pyproject.toml
```

测试使用模拟账号与服务, 不应配置真实通知 token 或真实站点凭据. CI 不负责启动生产调度、读取生产密钥或执行真实签到. Docker 不可用时只能检查 Compose/YAML 和脚本语法, 不能将其表述为镜像构建或容器运行成功.

## 故障排除

- 无法打开页面: 检查服务状态、端口占用和 SSH 转发. 默认只允许本机访问.
- 密钥读取失败: 检查文件为原始 32 字节, 以及容器 UID `10001` 的读取权限. 不要用 base64 文本替代原始文件.
- 人工接管不可用: 检查 Linux、DISPLAY/Xvfb、x11vnc、noVNC 与浏览器运行模式. Windows 普通启动不提供接管.
- `OAUTH_IDENTITY_NOT_CONFIGURED`: 检查 Identity 别名、类型和 Account 关联.
- `ACCOUNT_IDENTITY_PROXY_CONFLICT` / `SHARED_IDENTITY_PROXY_CONFLICT`: 统一同一身份的最终代理策略.
- `ACCOUNT_MISMATCH`: 核对目标站点用户名和 ID, 不要删除校验字段接受未知账号.
- 加密快照损坏或不兼容: 保留备份并核对密钥、操作系统与浏览器版本, 必要时重新登录.
- `RATE_LIMITED` / `ACCESS_BLOCKED`: 等待站点限制解除或联系站点, 不自动更换代理重试.
- HTTP 200 但业务失败: 检查任务结果和站点返回, HTTP 状态码不等于签到成功.

本项目只操作本人或明确获授权的账号, 使用前请遵守相关网站条款. 贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md), 许可见 [LICENSE](LICENSE).
