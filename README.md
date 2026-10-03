# MijiaMCP

基于 [mijiaAPI](https://github.com/Do1e/mijia-api) 提供米家 Streamable HTTP MCP 服务，支持通过 Agent 查询和控制设备，使用 OAuth 或 API Key 认证、uv 管理 Python 依赖。

## 生成随机 API Key

在仓库目录执行：

```bash
uv run --locked python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

将生成的 Key 填入 `ALLOWED_API_KEYS`。该变量必须是非空 JSON 数组，每个 Key 至少包含 32 个不含空白的 ASCII 字符；数组中的任意 Key 均有效。

## 本地开发与 Inspector 调试

### 启动服务

准备 Python 3.12 和 uv。首次使用时复制配置模板：

```bash
cp .env.example .env
```

编辑 `.env`，将示例中的占位值替换为刚生成的 Key：

```dotenv
ALLOWED_API_KEYS='["YOUR_RANDOM_API_KEY_1_AT_LEAST_32_CHARS"]'
APP_PORT=8080
MIJIA_DATA_DIR=./.data
```

允许多个 Key 时，在数组中继续添加字符串：

```dotenv
ALLOWED_API_KEYS='["YOUR_RANDOM_API_KEY_1_AT_LEAST_32_CHARS", "YOUR_RANDOM_API_KEY_2_AT_LEAST_32_CHARS"]'
```

启动脚本会同步锁定依赖并运行服务：

```bash
./local_run.sh
```

默认 MCP 地址为 `http://127.0.0.1:8080/mcp`，健康检查地址为 `http://127.0.0.1:8080/health`。修改 `APP_PORT` 后使用对应端口。

测试与静态检查：

```bash
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
```

### 使用 Inspector

本地安装 Node.js 22.19.0 或更高版本及 pnpm，然后启动官方 [MCP Inspector](https://github.com/modelcontextprotocol/inspector)：

```bash
pnpx @modelcontextprotocol/inspector@latest
```

按终端提示打开网页，在 Inspector v2 中配置：

1. 新增服务器，传输类型选择 **HTTP / Streamable HTTP**。
2. URL 填写 `http://127.0.0.1:8080/mcp`；连接远程服务时填写其完整 HTTPS `/mcp` 地址。
3. 在 **Server Settings → Headers** 添加 `Authorization`，值为 `Bearer YOUR_API_KEY`，替换为 `ALLOWED_API_KEYS` 中的一个 Key。
4. 保存并连接，在 **Tools** 页面查看工具和执行结果。

## 客户端连接与首次扫码

客户端需支持 Streamable HTTP，并在每次请求中携带 Bearer 凭证。当前服务同时接受两种凭证：

| Bearer 中的值 | 校验方式 |
| --- | --- |
| API Key | 与 `ALLOWED_API_KEYS` 中的密钥匹配 |
| OAuth `access_token` | 查询令牌记录，检查有效期、权限及对应 API Key 是否仍有效 |

直接使用 API Key 时，请求头为：

```http
Authorization: Bearer YOUR_API_KEY
```

只发送 `ALLOWED_API_KEYS` 数组中的一个 Key；`Authorization: Bearer <API_key>` 仍然生效。
使用 OAuth 授权后获得的 `access_token` 时，请求头为：

```http
Authorization: Bearer YOUR_ACCESS_TOKEN
```

OAuth `access_token` 是服务随机生成的独立凭证，与 API Key 不相等，也不是 API Key 的编码结果。
API Key 用于所有者在授权页确认授权，也可以直接作为 Bearer 凭证；OAuth 客户端后续使用
`access_token` 调用工具，无需持有该 API Key。

`ACCESS_TOKEN_EXPIRE_SECONDS` 只控制新签发的 OAuth `access_token`，不控制 API Key 的有效期。
API Key 没有时间过期限制；从 `ALLOWED_API_KEYS` 中移除并重新部署或重启服务加载新配置后，
该 Key 以及通过它授权出来的 `access_token` 都会失效，包括永久有效的 token。

未提供凭证、凭证无效或 OAuth token 已过期时会返回 **401**；`/health` 无需认证。

### ChatGPT / Codex 云端插件认证

云端插件的通用 `mcp.json` 只包含服务器 URL，不包含 `Authorization` 或密钥。
Codex 会过滤插件包中的 `Authorization`，应通过客户端的 OAuth 连接保存认证。

服务设置 `MIJIA_PUBLIC_URL` 为完整 HTTPS 源地址（不含 `/mcp`），即可启用 OAuth。
Railway 自动提供 `RAILWAY_PUBLIC_DOMAIN` 时，服务默认使用该域名，无需额外配置。
本地 OAuth 调试可设置 `MIJIA_PUBLIC_URL=http://localhost:8080`。

客户端选择 OAuth，填写现有 HTTPS `/mcp` URL。连接时会打开本服务的授权页，
显示客户端自报名称、实际回调地址和设备控制权限。确认客户端可信后输入现有 API Key，
点击“授权连接”。API Key 只发送到本服务，不传给客户端；客户端收到专属 `access_token`。
这次授权与后续米家账号扫码登录是两个独立步骤。

服务提供标准认证发现、动态客户端注册、S256 PKCE 和撤销端点。
授权码换取随机生成的 `access_token`，不使用 JWT，不签发 `refresh_token`，也不支持刷新授权。
`ACCESS_TOKEN_EXPIRE_SECONDS` 控制新签发 access_token 的有效期，单位为秒，
默认 `2592000`（30 天），允许正整数或 `-1`；`-1` 表示永久有效，`0` 和其他负数拒绝启动。
例如 `2592000` 为 30 天。永久 token 的响应不包含 `expires_in`，服务端没有时间过期限制，
但撤销 token 或删除对应 API Key 仍会使它失效。
返回的 `expires_in` 与服务端实际校验使用同一配置；到期后客户端需要重新授权连接。
修改配置只影响新签发的 token，重启或调长配置不会延长已签发 token 的失效时间。
这个配置不改变直接 Bearer API Key 或上游米家登录凭证的有效期。
令牌绑定本服务的 `/mcp` 资源和 `mijia` scope。现有 Key 客户端保持兼容。
删除 `ALLOWED_API_KEYS` 中某个 Key 后，该 Key 授权的 OAuth 令牌也会失效。

客户端注册、授权码和 access_token 状态持久化到 `MIJIA_DATA_DIR/oauth.sqlite3`，权限为 `0600`；令牌和授权码只存摘要。
Railway 需保持原有 `/data` Volume 挂载，确保重启后保留客户端注册与授权状态。
不要提交该数据库、米家凭证或真实 API Key 到仓库或插件包。

在 Railway 中创建挂载到 `/data` 的 Volume，并将 `MIJIA_DATA_DIR` 设置为 `/data`。
不要沿用本地开发的 `./.data`。省略该变量时服务会采用 Railway 的 Volume 挂载路径；
在 Railway 环境缺少 Volume 或数据目录位于 Volume 外时，服务会拒绝启动，避免
看似部署成功、随后丢失登录和 OAuth 注册。如果旧部署已丢失注册，ChatGPT 会继续
复用原客户端 ID，需要恢复原 OAuth 数据库或重建客户端连接；重试 API Key 无法修复。

#### 浏览器 OAuth 回归验证

运行 `uv run --locked python scripts/oauth_browser_smoke.py`，在浏览器打开
`http://localhost:8927/start`，输入终端显示的测试专用 Key。成功页面应显示
`Browser OAuth passed` 和 `14 tools`。该脚本使用临时数据库和虚构 Key，
不加载生产凭证、不访问真实设备；按 Ctrl+C 结束。

此验证覆盖普通 HTTP 单元测试无法发现的浏览器策略：授权页必须使用
`Referrer-Policy: same-origin`，否则 Chromium 的表单 POST 会携带 `Origin: null`
而被来源校验拒绝。CSP 的 `form-action` 还必须允许本次已验证的客户端回调源，
否则授权码已签发但浏览器会阻止跨站回调。不得通过接受任意 Origin、移除 CSRF
校验或使用通配 CSP 来规避此问题。

首次使用时，在 Inspector 的 **Tools** 页面依次执行以下工具，参数均为 `{}`：

| 工具 | 操作 |
| --- | --- |
| `login` | 打开返回的二维码链接，在 2 分钟内用米家 App 扫码 |
| `login_status` | 查询登录结果，仍在等待时再次执行 |
| `list_homes` | 登录成功后查询家庭 |
| `list_devices` | 查询设备，确认米家账号连接正常 |

扫码后需要执行 `login_status`，确认成功后再调用设备工具。登录凭证保存在 `MIJIA_DATA_DIR` 下的 `auth.json`，本地默认为 `.data/auth.json`，重启后自动加载。凭证失效时重新扫码登录。

## 参考与许可证

- [米家 MCP 文档](https://mijia-api.do1e.com/usage/mcp)
- [mijiaAPI 源码](https://github.com/Do1e/mijia-api)
- [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
- [Inspector 服务器配置](https://github.com/modelcontextprotocol/inspector/blob/main/docs/mcp-server-configuration.md)
- [uv 文档](https://docs.astral.sh/uv/)

项目许可证为 GPL-3.0-or-later；米家能力来自同样采用 GPL-3.0-or-later 的 `mijiaAPI` 项目，上游许可证见其仓库。
