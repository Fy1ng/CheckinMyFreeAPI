# Go 独立应用

Go 版将后端与现有 WebUI 编译为独立程序, 使用纯 Go SQLite, 无需安装 Python, Node.js 或 Chromium. AnyRouter, AgentRouter, 代理, 通知, Status, 加密备份以及密码和 Passkey 两种管理认证沿用现有功能与安全规则.

当前 Python 版和既有服务器部署保持原状. 构建, 下载或启动 Go 版不会自动替换服务器程序, 也不会自动安装系统自启项.

## 下载后的文件

| 路径 | 用途 |
|---|---|
| `windows-amd64/checkin.exe` | Windows 64 位静默程序, 不显示控制台 |
| `windows-amd64/checkin-cli.exe` | 相同功能的控制台版本, 用于诊断和命令行管理 |
| `linux-amd64/checkin` | Linux x86_64 |
| `linux-arm64/checkin` | Linux ARM64 |
| `SHA256SUMS` | 本次构建的二进制 SHA256 清单, 使用相对路径 |
| `GO_DEPENDENCY_LICENSES.txt` | 编译进入程序的 Go 标准库和第三方模块许可文本 |

Windows 两个程序操作相同的数据格式. 同一个数据目录只允许运行一个实例. 建议将程序放在固定的本地目录, 再配置自启或服务, 避免移动后留下失效的启动路径.

Linux 在文件复制后执行 `chmod 0755 checkin`. 从 CI 下载的 artifact 可能不保留执行权限. Linux 可在解压根目录运行 `sha256sum --check SHA256SUMS`; Windows 可用 `Get-FileHash -Algorithm SHA256` 与清单核对.

## Windows 首次运行

双击 `checkin.exe` 即可后台启动, 不自动打开浏览器. 手动访问 `http://127.0.0.1:8765`, 或运行:

```powershell
.\checkin-cli.exe open
```

首次通过本机页面设置 16 至 512 字符的管理密码. 未完成初始化时不会执行账号任务. 原始 32 字节主密钥由程序生成, 需随数据妥善备份. 初始化只允许本机或受限 SSH 转发入口, 不从公网设置第一份管理密码.

默认数据目录为 `%APPDATA%\CheckinMyFreeAPI`, 包含 `webui.sqlite3`, `master.key`, `go-runtime.json` 和 `server.log`. 可通过参数指定其他私有目录:

```powershell
.\checkin.exe serve --data-dir 'D:\CheckinMyFreeAPI\data'
.\checkin-cli.exe open --port 8765
```

需要查看前台启动错误时, 先从面板退出已有实例, 再运行:

```powershell
.\checkin-cli.exe serve --data-dir 'D:\CheckinMyFreeAPI\data'
```

前台使用 `Ctrl+C` 停止. 静默实例可通过面板退出. `server.log` 达到 5 MiB 后轮换, 最多保留三个历史日志. 程序不会将站点密码, Cookie, 令牌或原始响应写入日志. GUI 版不显示命令输出, 版本, 离线恢复及诊断命令建议使用 `checkin-cli.exe`.

## 启动签到

Go 运行设置提供启动签到开关和 0 至 300 秒的启动等待时间. 新实例默认启用, 等待 10 秒. 它与原有 Cron 或间隔计划分别配置.

- 每次应用启动只发起一轮启动任务, 仅处理已保存并启用的账号. 启动时为空白或尚未初始化的实例不会签到, 随后首次保存账号也不会补触发启动任务.
- 按 UTC+8 判断当天. 同一账号和凭据, 身份, 代理绑定下, 当天已有确认成功记录时跳过, 保留可查的跳过原因.
- 启动任务与手动, 定时, 余额及备份任务共用串行执行边界, 不并发操作账号会话.
- 网络尚未就绪时仅对任务前的连接检查有限等待. 不重发结果不确定的签到或 Agent 登录写入.
- 凭据失效, CF, 限流和未知写入的暂停继续生效. 重启不能解除暂停; 未知结果必须人工核对, 限流必须等待期限.

首次初始化或迁移验证期间可关闭启动签到, 配置核对完成后再启用. `go-runtime.json` 属于本机运行设置, 不保存账号凭据, 不改变账户配置 schema. 在线备份恢复和离线灾难恢复后, 自动任务保持关闭, 包括 Go 启动签到.

## Windows 自启与系统服务

普通自启指当前用户登录 Windows 后运行, 不需要管理员权限. 可在面板控制, 或使用静默程序注册和移除:

```powershell
$data = Join-Path $env:APPDATA 'CheckinMyFreeAPI'
.\checkin.exe autostart install --data-dir $data
.\checkin.exe autostart remove --data-dir $data
```

注册位置为当前用户的 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, 项名为 `CheckinMyFreeAPI`. 使用 `checkin.exe` 注册可确保启动时不弹控制台. 自启项包含程序, 数据, 主密钥和监听设置的路径, 不包含账号密码或 Cookie. 移动程序或更改这些路径后应重新注册.

如需 Windows 开机后在无人登录时也运行, 可在管理员 PowerShell 中安装系统服务. 先退出普通实例, 并移除该实例的登录自启项, 再执行:

```powershell
$data = Join-Path $env:APPDATA 'CheckinMyFreeAPI'
.\checkin-cli.exe service install --data-dir $data
.\checkin-cli.exe service start --data-dir $data
.\checkin-cli.exe service status --data-dir $data
```

服务名为 `CheckinMyFreeAPI`, 使用延迟自动启动. 默认以 LocalSystem 运行, 因此应明确指定已初始化的绝对数据目录, 避免误用系统账户默认目录. 数据目录及主密钥须由预期用户, SYSTEM 和管理员保护, 不放在共享或其他用户可读的目录. 登录自启通常已满足个人电脑后台运行需求.

停止和卸载服务:

```powershell
.\checkin-cli.exe service stop --data-dir $data
.\checkin-cli.exe service uninstall --data-dir $data
```

卸载仅移除服务注册, 不清空账号或数据库. 升级二进制前先停止服务, 保留数据和主密钥, 替换后再启动.

## Linux 运行与开机自启

Linux 默认数据目录为 `$XDG_CONFIG_HOME/CheckinMyFreeAPI`, 未设置时为 `$HOME/.config/CheckinMyFreeAPI`. 可使用固定的显式目录:

```bash
chmod 0755 ./checkin
./checkin serve --data-dir "$HOME/.local/share/CheckinMyFreeAPI"
```

临时后台运行可添加 `--background`, 不自动打开浏览器. 长期运行建议使用 systemd 用户服务:

```bash
./checkin autostart install --data-dir "$HOME/.local/share/CheckinMyFreeAPI"
systemctl --user start checkinmyfreeapi.service
./checkin autostart status --data-dir "$HOME/.local/share/CheckinMyFreeAPI"
```

默认随用户会话启动. 如需无登录会话也在开机后运行, 可由管理员执行 `sudo loginctl enable-linger "$USER"`, 使该用户的 systemd 服务管理器在开机后运行. 程序仍以该用户身份运行. 取消时执行 `autostart remove`; 通过 `systemctl --user stop checkinmyfreeapi.service` 停止当前实例.

也提供 `service install|start|stop|status|uninstall` 管理 `/etc/systemd/system/checkinmyfreeapi.service`, 这些系统级操作需要 root. 默认系统级 unit 使用系统身份; 如需专用非 root 身份, 管理员应为 unit 配置合适的 `User`, `Group` 和数据目录权限. 优先使用用户服务或下面的非 root 容器方式.

服务的执行路径和数据路径使用绝对路径. unit 包含故障重启, 私有临时目录, 只读系统目录和限制写入数据目录的设置. 不补跑停机期间漏过的原有定时计划.

## 配置与认证兼容

Go 版保留 `CHECKIN_WEB_DATA_DIR`, `CHECKIN_WEB_KEY_FILE`, `CHECKIN_WEB_HOST`, `CHECKIN_WEB_PORT`, `CHECKIN_WEB_PASSWORD_FILE`, `CHECKIN_WEB_PASSWORD`, `CHECKIN_WEB_PUBLIC_URL` 和 `CHECKIN_WEB_TRUSTED_PROXY_IPS`. 服务不自动读取 `.env`. 对应命令行参数优先于环境变量, 详见 `checkin-cli.exe --help` 或 `./checkin --help`.

默认仅监听 `127.0.0.1:8765`. 如已占用, 使用 `--port 18765`, 打开页面时也使用该端口. `open` 命令只打开本机浏览器, 不启动服务, 不改变认证设置.

保留 Python 版 SQLite 中的加盐管理密码哈希, Passkey 公钥和计数器, 安全模式以及用户标识. Passkey 模式不会因更换后端退回公网密码登录. Passkey 继续绑定原 RP ID 和精确 origin, 从原 HTTPS 地址改成本机 HTTP, 换域名或端口, 都可能使原密钥无法用于新入口. 应在保留原入口的条件下验证, 或通过离线安全恢复重新绑定.

公网仍应由反向代理提供 HTTPS. 需要显式配置 `--public-url https://checkin.example.com` 和实际的单个可信反向代理 IP, 不以任意请求头扩展可信域名. 不直接公开应用的明文监听端口. 本机与公网会话隔离, Origin 和 CSRF 检查, 登录限流, Passkey 二次验证保持生效.

## 从 Python 版迁移与回退

先在 Python 面板关闭自动签到, 余额监测, 自动通知和自动备份, 停止 Python 服务后备份整个数据目录及其对应的原始 `master.key`. 主密钥可能在数据目录之外, 必须单独复制. 不要生成新密钥覆盖已有密钥, 不要让两种后端同时连接同一个数据库.

推荐将副本放到新的私有 Go 数据目录, 原数据与原程序保留作为回退. 在第一次启动 Go 版前, 在新数据目录写入以下 `go-runtime.json`, 防止迁移检查期间自动签到:

```json
{"revision":0,"run_on_startup":false,"startup_delay_seconds":10}
```

将原 `webui.sqlite3` 和所需数据文件复制到新目录, 将原始主密钥复制到私有密钥位置, 然后显式指定:

```powershell
.\checkin-cli.exe serve --data-dir 'D:\CheckinGo\data' --key-file 'D:\CheckinGo\keys\master.key'
```

Linux 使用相同参数, 数据目录建议 `0700`, 数据和密钥文件建议 `0600`, 由实际服务用户持有. 已有数据库缺少匹配主密钥时, 程序拒绝启动.

先核对账号, 代理, 历史, 余额, 认证模式, Passkey 和备份预览. 保存配置本身不签到, 余额页面自动轮询只读取缓存. 只有用户选择手动签到或重新启用自动任务时才进行相应站点操作. 账户原有暂停和未知写入记录保留.

回退时停止 Go 版, 使用迁移前保留的 Python 程序, 数据库快照和对应主密钥重新启动. 不将 Go 版运行期间的新结果凭空合并回旧快照. 若迁移后已发生真实签到, 回退后的首次执行前应重新核对当天结果, 避免旧快照缺失这些记录.

## 离线恢复与登录安全恢复

`.nab` 备份继续使用独立恢复密码, 包含加密的一致数据库快照和主密钥. 可在不启动服务的情况下检查:

```powershell
.\checkin-cli.exe backup inspect --file '.\saved.nab'
```

恢复密码通过终端安全输入. 静默或非交互场景可指定受保护的 `--recovery-password-file`, 不将真实密码放在命令参数中. 离线灾难恢复只写入空目标数据目录和空密钥位置:

```powershell
.\checkin-cli.exe backup restore --file '.\saved.nab' --data-dir 'D:\RestoredCheckin\data' --key-file 'D:\RestoredCheckin\keys\master.key' --confirm
```

同一实例的在线恢复保留当前管理员认证模式和 Passkey, 不从旧备份复活已删除密钥或重新开启公网密码入口. 恢复后自动任务关闭, 重新登录核对后启用.

丢失全部 Passkey 或入口 origin 改变时, 先停止服务, 再通过本机或 SSH 执行:

```powershell
.\checkin-cli.exe security reset --data-dir 'D:\CheckinMyFreeAPI\data' --confirm
```

该命令必须取得服务独占锁, 恢复密码模式并使旧管理会话失效, 保留现有管理密码, 账户和历史. 只有明确需要撤销全部已有密钥时才添加 `--clear-passkeys`. 该操作不会签到或发送通知.

## 构建与 CI

在源码根目录使用 Go 1.26.10 或更高版本, 执行:

```powershell
.\scripts\build-go.ps1 -Version v1.0.0
```

或:

```bash
bash scripts/build-go.sh --version v1.0.0
```

默认生成 `dist/go/` 下四个二进制和 `SHA256SUMS`. 所有目标使用 `CGO_ENABLED=0`, `-trimpath` 和 `main.version`, Windows GUI 额外使用 `-H=windowsgui`. 不需要 C 编译器. 不指定版本时使用 Git 描述, 无 Git 信息时使用 `dev`. 版本只允许 ASCII 字母, 数字, 点, 下划线, 加号和连字符.

可通过 PowerShell 的 `-Targets windows-amd64` 或 Bash 的末尾目标参数限制构建, 通过 `-OutputDir` 或 `--output` 修改输出目录. 校验清单只包含本次构建的目标. 构建脚本不运行应用, 不注册自启, 不访问真实账号.

`go-check.yml` 在 Ubuntu 和 Windows 执行隔离测试与 vet, 在 Linux 使用固定版本 govulncheck 扫描, 交叉构建 Windows/Linux amd64/Linux arm64 并保存短期 artifact. Actions 固定完整提交 SHA, 令牌仅允许读取源码. CI 不安装用户自启项, 不执行真实签到或发送通知, 浏览器验收为另行启用的隔离测试.

## 可选的 Linux 容器

`Dockerfile.golang` 使用 Go 多阶段构建, 运行层为包含 CA 与时区数据的 distroless static 镜像. 最终以 UID/GID `10001:10001` 运行, 无 Python, 浏览器, shell 或动态 C 运行库. 可直接构建, 无需服务器安装 Go:

```bash
docker build -f Dockerfile.golang --build-arg VERSION=v1.0.0 -t checkinmyfreeapi:go-v1.0.0 .
mkdir -p go-data go-secrets
# 使用本机编辑器创建 go-secrets/web-password, 填入至少 16 字符的首次管理密码.
sudo chown 10001:10001 go-data
sudo chmod 0700 go-data
sudo chown 10001:10001 go-secrets/web-password
sudo chmod 0600 go-secrets/web-password
docker run -d --name checkin-go --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --cpus 1 \
  -p 127.0.0.1:8765:8765 \
  -v "$PWD/go-data:/data" \
  -v "$PWD/go-secrets/web-password:/run/secrets/web-password:ro" \
  -e CHECKIN_WEB_PASSWORD_FILE=/run/secrets/web-password \
  checkinmyfreeapi:go-v1.0.0
```

只有容器内部监听 `0.0.0.0`, 宿主映射仍限制为 `127.0.0.1`. Docker bridge 会改变应用看到的来源 IP, 因此空白容器通过上述只读文件设置首次管理密码, 然后从本机或 SSH 转发入口登录. 不为通过初始化检查而扩大可信代理范围, 不将无初始化的管理页面直接开放到公网. 已有管理员时保留数据库中的密码摘要. 可通过 `http://127.0.0.1:8765/healthz` 检查健康状态. 该最小镜像不包含用于容器内诊断的 shell 或 curl.

默认数据与生成的主密钥均在 `/data`. 迁移既有独立密钥时, 额外挂载原密钥为只读文件并设置 `CHECKIN_WEB_KEY_FILE=/keys/master.key`, 不用新生成密钥替换它. 准备发布时可用 `GO_IMAGE` 和 `RUNTIME_IMAGE` 构建参数将已核验基础镜像固定为 digest. 多平台构建可使用 Docker BuildKit 的 `--platform`, 相应架构的可执行文件会在构建阶段生成.

构建阶段的内存需求高于运行阶段. 小内存服务器可先在其他机器构建二进制或镜像, 再传输到服务器运行.

容器不会修改现有 Python Compose 或其他服务. 需要替换既有部署时, 应先单独验证数据副本, 认证和回滚路径, 再安排停止旧实例与切换入口.
