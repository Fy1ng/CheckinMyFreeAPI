# 开发说明

本项目为 HTTP-only NewAPI WebUI, 仅支持 AnyRouter 与 AgentRouter. 生产运行不使用浏览器、OAuth、自定义站点或远程桌面.

使用 Python 3.11 与 uv, 执行 `uv sync --frozen`. 代码沿用 Ruff 的 Tab 缩进与单引号. 检查命令见 README. Playwright 仅为开发界面测试依赖.

测试使用 httpx.MockTransport、本地 aiohttp fixture 和模拟通知, 不访问真实站点、不使用真实凭据、不发送真实通知. 新增凭据字段必须同时覆盖加密、脱敏、秘密保留/清除和账号绑定测试. 写请求结果不确定不得通过重试获得绿色测试结果.

修改接口需保留 WebUI 的 CSRF、loopback 限制、版本冲突与未知结果锁. 配置迁移必须归档原始密文, 原子提交并可幂等重启. 不把 API key、Cookie、密码、真实数据目录或数据库纳入版本控制.

提交与发布范围由维护者明确授权, 默认只做本地验证与提交.
