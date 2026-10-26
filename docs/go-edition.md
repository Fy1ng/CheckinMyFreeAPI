# Go 独立应用

Go 版采用 Go 业务层 + Wails v3 桌面壳 + 共享 WebUI/JSON API. HTML, CSS 和 JavaScript 与后端按职责分离, 构建时嵌入同一个可执行文件, 无需额外运行前端服务器或安装 Python/Node.js. 桌面窗口使用系统 WebView, 服务器和 CLI 使用无 GUI 构建.

AnyRouter, AgentRouter, 代理, 通知, Status, 加密备份以及密码和 Passkey 两种管理认证沿用现有功能与安全规则. 桌面 WebView 仅显示管理界面, 站点签到仍使用原有 HTTP 流程, 不通过 WebView 自动登录站点或处理验证码.

当前 Python 版和既有服务器部署保持原状. 构建, 下载或启动 Go 版不会自动替换服务器程序, 也不会自动安装系统自启项.

## 下载后的文件

| 路径 | 用途 |
|---|---|
| `windows-amd64/checkin.exe` | Windows 64 位桌面程序, 包含窗口和托盘, 不显示控制台 |
| `windows-amd64/checkin-cli.exe` | 无 GUI 的 CLI/服务器程序, 用于诊断和服务管理 |
| `linux-amd64/checkin` | Linux x86_64 无 GUI 服务器 |
| `linux-arm64/checkin` | Linux ARM64 无 GUI 服务器 |
| `linux-desktop-amd64/checkin` | 可选的 Linux x86_64 GTK 桌面构建 |
| `linux-desktop-arm64/checkin` | 可选的 Linux ARM64 GTK 桌面构建 |
| `SHA256SUMS` | 本次构建的二进制 SHA256 清单, 使用相对路径 |
| `GO_DEPENDENCY_LICENSES.txt` | 编译进入程序的 Go 标准库和第三方模块许可文本 |

Windows 两个程序操作相同的数据格式. 同一个数据目录只允许一个后端运行; 桌面壳可在核实身份后连接该目录已有的后台服务, 不重新启动签到或打开第二份数据库执行器. 建议将程序放在固定的本地目录, 再配置自启或服务, 避免移动后留下失效的启动路径.

Linux 在文件复制后执行 `chmod 0755 checkin`. 从 CI 下载的 artifact 可能不保留执行权限. Linux 可在解压根目录运行 `sha256sum --check SHA256SUMS`; Windows 可用 `Get-FileHash -Algorithm SHA256` 与清单核对.

## Windows 首次运行

双击 `checkin.exe` 打开桌面控制台, 同时启动后台任务和托盘. Windows 需要 Microsoft Edge WebView2 Runtime; 桌面窗口使用该系统组件, 不随程序打包一份 Chromium. 无 GUI 的 `checkin-cli.exe serve` 不需要 WebView2.

关闭窗口会隐藏到托盘, 不停止签到或后续计划. 从托盘打开控制台或 Status; 选择退出才结束当前桌面实例. 再次启动同一数据目录的桌面程序会激活已有窗口. 通过系统服务运行的后台由服务管理器控制, 退出连接它的桌面窗口不会停止该服务.

普通再次打开会保留当前页面和未保存草稿. 托盘的 Status 入口用于切换到状态页. `Ctrl+Q` 与托盘退出具有相同含义; 从页面选择退出后台程序仍需明确确认. 启动失败会在数据目录的 `desktop.log` 写入固定原因代码, 普通启动同时显示错误提示, 隐藏启动不弹出错误窗口.

需要保留托盘但启动时不显示窗口时运行:

```powershell
.\checkin.exe app --hidden
```

也可通过系统浏览器访问同一套管理界面, 默认地址为 `http://127.0.0.1:8765`, 或运行:

```powershell
.\checkin-cli.exe open
```

本地桌面模式直接进入管理面板, 首次无需设置管理密码, 也没有登录, Passkey 或管理员重验步骤. 同一个本地后台的浏览器入口同样免管理认证. 后台仍会生成原始 32 字节主密钥并加密账号凭据, 需随数据妥善备份. 添加账号仍需填写站点实际凭据; 创建和恢复加密备份仍使用独立恢复密码解密文件.

桌面 `app` 在未配置公网入口或可信代理时默认启用本地模式. 本地模式只允许 `127.0.0.1` 或 `::1` 监听, 拒绝公网入口, 转发头和跨站访问, 页面来源与后台 CSRF 校验保持生效. 本地无 GUI 运行可使用 `checkin-cli.exe serve --local`. 常规 `serve` 及公网配置仍沿用服务器认证; 桌面连接既有服务器后台时按该后台的认证规则访问, 不静默降级服务器.

默认数据目录为 `%APPDATA%\CheckinMyFreeAPI`, 包含 `webui.sqlite3`, `master.key`, `go-runtime.json` 和 `server.log`. 可通过参数指定其他私有目录:

```powershell
.\checkin.exe app --data-dir 'D:\CheckinMyFreeAPI\data'
.\checkin-cli.exe open --port 8765
```

需要查看前台启动错误时, 先从面板退出已有实例, 再运行:

```powershell
.\checkin-cli.exe serve --data-dir 'D:\CheckinMyFreeAPI\data'
```

前台服务器使用 `Ctrl+C` 停止. 桌面实例可通过托盘退出, 窗口隐藏期间后台继续工作. `server.log` 达到 5 MiB 后轮换, 最多保留三个历史日志. 程序不会将站点密码, Cookie, 令牌或原始响应写入日志. GUI 版不显示命令输出, 版本, 离线恢复及诊断命令建议使用 `checkin-cli.exe`.

## 启动签到

Go 运行设置提供启动签到开关和 0 至 300 秒的启动等待时间. 新实例默认启用, 等待 10 秒. 它与原有 Cron 或间隔计划分别配置. 空白本地实例没有账号时不会发送签到请求.

- 每次后端启动只发起一轮启动任务, 仅处理已保存并启用的账号. 打开第二个窗口或连接已有后台不会再触发一轮. 启动时为空白或尚未初始化的实例不会签到, 随后首次保存账号也不会补触发启动任务.
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

注册位置为当前用户的 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, 项名为 `CheckinMyFreeAPI`. 桌面自启使用 `app --hidden`, 登录后保留托盘并运行后台, 不弹出控制台或主窗口. 自启项包含程序, 数据, 主密钥和监听设置的路径, 不包含账号密码或 Cookie. 移动程序或更改这些路径后应重新注册. 旧版只运行 `serve` 的自启项可通过重新启用桌面自启更新, 原有后台模式仍可显式使用.

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

可选的 Linux 桌面版本使用 GTK 3 和 WebKitGTK 4.1, 需要图形会话与相应系统库. 运行桌面构建中的 `./checkin app`, 或使用 `app --hidden` 仅保留托盘. 托盘显示取决于桌面环境的支持. 在桌面版启用登录后自启会创建当前用户的 `~/.config/autostart/checkinmyfreeapi.desktop` (设置 XDG_CONFIG_HOME 时沿用对应目录), 在图形会话中执行 `app --hidden`. 上述 systemd 用户服务用于无 GUI 服务器, 两种自启应按实际运行版本选择. 无图形桌面的服务器继续使用 `linux-amd64` 或 `linux-arm64` 目录下的无 GUI 程序, 无需安装这些桌面库.

## 配置与认证兼容

Go 版保留 `CHECKIN_WEB_DATA_DIR`, `CHECKIN_WEB_KEY_FILE`, `CHECKIN_WEB_HOST`, `CHECKIN_WEB_PORT`, `CHECKIN_WEB_PASSWORD_FILE`, `CHECKIN_WEB_PASSWORD`, `CHECKIN_WEB_PUBLIC_URL` 和 `CHECKIN_WEB_TRUSTED_PROXY_IPS`. 服务不自动读取 `.env`. 对应命令行参数优先于环境变量, 详见 `checkin-cli.exe --help` 或 `./checkin --help`.

默认仅监听 `127.0.0.1:8765`. 如已占用, 使用 `--port 18765`, 打开页面时也使用该端口. `open` 命令只打开本机浏览器, 不启动服务, 不改变认证设置.

保留 Python 版 SQLite 中的加盐管理密码哈希, Passkey 公钥和计数器, 安全模式以及用户标识. Passkey 模式不会因更换后端退回公网密码登录. Passkey 继续绑定原 RP ID 和精确 origin, 从原 HTTPS 地址改成本机 HTTP, 换域名或端口, 都可能使原密钥无法用于新入口. 应在保留原入口的条件下验证, 或通过离线安全恢复重新绑定.

公网仍应由反向代理提供 HTTPS. 需要显式配置 `--public-url https://checkin.example.com` 和实际的单个可信反向代理 IP, 不以任意请求头扩展可信域名. 不直接公开应用的明文监听端口. 本机与公网会话隔离, Origin 和 CSRF 检查, 登录限流, Passkey 二次验证保持生效.

桌面窗口继续访问同源 HTTP API. 本地模式按显式启动策略取消管理身份认证, 不通过请求头或前端参数开启; 服务器模式保留原有登录. 两种模式都保持 Origin/CSRF 校验, 不将任意 WebView 地址列为可信来源. 桌面壳通过私有本机记录和随机挑战核实已有后台的身份, 不把端口占用或通用健康响应当作可连接的服务.

`desktop-control.json` 只用于同一私有数据目录的本机后台身份证明, 不提供账号操作能力. `desktop-instance.key` 用于桌面单实例通信, 与账号加密主密钥独立. Windows 的 `desktop-webview/` 包含桌面浏览器缓存和管理会话, 应与整个私有数据目录一起保护, 不提交到 Git 或上传为诊断附件. Linux WebKit 使用系统管理的 WebView 数据上下文. 正式构建不会打开远程调试端口.

桌面加载可信管理页面后会安装页面侧导航防护, 阻止常见外链, 外部表单和弹出窗口; 可按提示复制链接到系统浏览器. 该防护不代替后端的来源检查, 也不是 WebView 引擎的完整原生导航策略. 本地控制台路径与已登录的加密备份下载继续可用.

本地模式不显示 Passkey 或登录安全入口, 原有认证数据仍保留. 在服务器模式或连接服务器后台时, Passkey 是否可在内嵌窗口使用取决于系统 WebView 的支持; 不支持时可使用系统浏览器管理. 原有 RP ID/origin 绑定继续生效, 不自动将公网密钥迁移到本机地址. WebView 的缓存目录不作为站点账号备份, 备份和恢复继续使用 `.nab`.

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

同一实例的在线恢复保留当前管理员认证模式和 Passkey, 不从旧备份复活已删除密钥或重新开启公网密码入口. 本地模式恢复无需管理员密码或 Passkey, 恢复完成后自动回到面板; 服务器模式仍按当前策略重验. 恢复后自动任务关闭, 核对后再启用.

空白本地实例没有用户设置的管理员密码, 只保留用于数据格式兼容的随机不可见摘要. 将这份数据用于服务器模式前, 停止所有使用该数据的实例, 显式设置服务器管理密码:

```powershell
.\checkin-cli.exe security set-password --data-dir 'D:\CheckinMyFreeAPI\data' --confirm
```

新密码在终端隐藏输入两次, 非交互场景可用受保护的 `--password-file`. 该命令必须取得服务和任务独占锁, 保留账号, 原有认证模式及 Passkey. 已有服务器数据在本地模式使用时不会自动清空或替换管理员密码.

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

默认生成 `dist/go/` 下四个二进制和 `SHA256SUMS`: Windows Wails 桌面、Windows 无 GUI CLI、Linux amd64/arm64 无 GUI 服务器. 默认目标使用 `CGO_ENABLED=0`, `-trimpath` 和 `main.version`, 不需要 C 编译器. Windows 桌面额外使用 `-tags desktop,production -H=windowsgui`, CLI/服务器使用显式 `nogui` tag, 不导入 Wails.

Linux 桌面需要在匹配架构的 Linux 宿主原生构建, 使用 `CGO_ENABLED=1` 和 `-tags desktop,production,gtk3`. 例如 Ubuntu/Debian 安装开发库后执行:

```bash
sudo apt-get install pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libx11-dev
bash scripts/build-go.sh --version v1.0.0 linux-desktop-amd64
```

ARM64 宿主将最后一个目标改为 `linux-desktop-arm64`. PowerShell 的 `-Targets` 也接受这两个显式目标, 但同样需要匹配的 Linux 宿主. Windows 默认构建不会尝试链接 Linux 桌面库.

不指定版本时使用 Git 描述, 无 Git 信息时使用 `dev`. 版本只允许 ASCII 字母, 数字, 点, 下划线, 加号和连字符. 构建产物附带 Go 标准库及实际链接模块的许可文本; 桌面目标额外包含 Wails 及其依赖.

可通过 PowerShell 的 `-Targets windows-amd64` 或 Bash 的末尾目标参数限制构建, 通过 `-OutputDir` 或 `--output` 修改输出目录. 校验清单只包含本次构建的目标. 构建脚本不运行应用, 不注册自启, 不访问真实账号.

`go-check.yml` 在 Ubuntu 和 Windows 执行无 GUI 隔离测试与 vet, 并在 Windows 编译、测试桌面集成. Linux job 使用固定版本 govulncheck 分别扫描无 GUI 与 Windows 桌面链接路径. 独立 Ubuntu job 安装 GTK/WebKit 开发库, 在隔离显示会话下测试并原生构建 Linux 桌面. 普通 `main` 推送和 PR 只执行检查, 构建产物作为 artifact 保留 7 天. Actions 固定完整提交 SHA, 检查和构建任务使用 `contents: read`, 只有 Release 发布任务使用 `contents: write`. CI 不安装用户自启项, 不执行真实签到或发送通知, 真实 WebView/浏览器交互验收按测试开关另行启用.

## 自动发布 Release

`.github/workflows/release.yml` 在推送 `v*` 标签时运行, 只接受 `vMAJOR.MINOR.PATCH` 格式的有效 SemVer 版本, 如 `v1.0.0`, `v1.1.0-rc.1` 或 `v1.1.0+build.1`. 工作流复用现有 Python 和 Go 全部质量检查, 任一检查或构建失败都不会发布. 通过后使用对应版本的构建产物自动创建 [GitHub Release](https://github.com/Fy1ng/CheckinMyFreeAPI/releases) 并生成发行说明. 含预发布字段的版本标记为 prerelease, 不替代 latest.

每个 Release 提供以下附件, 其中 `<version>` 包含 `v` 前缀:

| 附件 | 内容 |
|---|---|
| `CheckinMyFreeAPI-<version>-windows-amd64.zip` | Windows 64 位桌面程序和无 GUI CLI |
| `CheckinMyFreeAPI-<version>-linux-amd64.tar.gz` | Linux x86_64 无 GUI 服务器 |
| `CheckinMyFreeAPI-<version>-linux-arm64.tar.gz` | Linux ARM64 无 GUI 服务器 |
| `CheckinMyFreeAPI-<version>-linux-desktop-amd64-ubuntu24.04.tar.gz` | Ubuntu 24.04 原生构建的 Linux x86_64 GTK 桌面程序 |
| `SHA256SUMS` | 上述压缩包的 SHA256 校验清单 |

压缩包沿用构建输出的目标子目录, 例如 `windows-amd64/checkin.exe` 或 `linux-amd64/checkin`. 每包附带 `README.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `GO_DEPENDENCY_LICENSES.txt` 和包内二进制 `SHA256SUMS`. Release 打包仅选取这些构建文件, 不包含数据目录, 主密钥或账号配置. Linux 桌面程序依赖 GTK 3 和 WebKitGTK 4.1, 不保证适用于任意旧发行版; 其他发行版可按上文在匹配宿主自行构建.

下载后先用 Release 的 `SHA256SUMS` 核对压缩包, 解压后再使用包内清单核对二进制. Linux 的 `.tar.gz` 保留可执行权限. Windows 可用 `Get-FileHash -Algorithm SHA256` 核对文件摘要.

维护者发布前先确认 `main` 的质量检查通过, 核对待发布提交范围及安全和隐私检查结果, 再在准备发布的提交上创建并明确推送版本标签:

```bash
git tag -a v1.0.0 -m 'Release v1.0.0'
git push origin v1.0.0
```

将示例版本替换为本次未使用的实际版本. 普通代码推送不会创建 Release, 发布新版本需另行推送标签.

## 可选的 Linux 容器

`Dockerfile.golang` 使用显式 `nogui` 构建和 Go 多阶段镜像, 运行层为包含 CA 与时区数据的 distroless static 镜像. 最终以 UID/GID `10001:10001` 运行, 不导入 Wails, 无 Python, 浏览器, GTK, WebView, shell 或动态 C 运行库. 可直接构建, 无需服务器安装 Go:

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
