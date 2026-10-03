# MijiaMCP on Railway

将现成的 [`mijiaAPI`](https://github.com/Do1e/mijia-api) MCP 工具作为 HTTP 服务部署到 Railway，用固定 API Key 访问。使用 **uv** 管理项目与锁定依赖。

```text
Agent / MCP Client
  └─ HTTPS + Authorization: Bearer <API Key>
       └─ Railway /mcp → 原有米家 MCP 工具 → 米家云
            └─ Volume /data/auth.json：米家扫码登录凭证
```

本仓库是部署适配器，不改写设备控制逻辑。依赖固定为 `mijiaAPI 4.4.0`、`FastMCP 3.4.7`，Python 3.12；Docker 中 uv 固定为 0.12.5，所有 Python 依赖锁定在 `uv.lock`。

## 目录结构

```text
src/
  server.py       服务配置、API Key 认证和 HTTP 启动入口
tests/
  test_server.py  认证、工具发现和登录持久化测试
local_run.sh      本地一键启动脚本（检查环境、同步依赖、启动服务）
pyproject.toml    uv 项目配置
uv.lock           依赖锁文件
Dockerfile        Railway 容器构建配置
```

## Railway 部署

### 1. 将仓库推送到 GitHub

在 GitHub 创建仓库，然后在本目录执行（替换远端 URL）：

```bash
git add .
git commit -m "Add Railway Mijia MCP with API key authentication"
git remote add origin https://github.com/YOUR-ACCOUNT/MijiaMCP.git
git push -u origin main
```

`.env`、米家 `auth.json`、本地 `.data/` 和 `.venv/` 已被忽略。Docker 构建上下文只允许部署文件进入镜像。

### 2. 创建 Railway 服务

选择 **New Project → Deploy from GitHub repo**，选中该仓库，根目录使用 `/`。

Railway 使用 `Dockerfile` 构建，通过 `python src/server.py` 启动服务。在服务部署设置中将 **Healthcheck Path** 设为 `/health`，重启策略设为 **On Failure**。第一次部署可能先因缺少 API Key 退出，补齐下一步配置后重新部署即可。

### 3. 配置 API Key

生成一个随机 Key：

```bash
uv run --locked python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

在 Railway 服务的 **Variables** 中填写：

| 变量 | 值 | 说明 |
| --- | --- | --- |
| `ALLOWED_API_KEYS` | JSON 数组，如 `["YOUR_API_KEY"]` | **必填**；数组非空，每个 Key 至少 32 个不含空白的 ASCII 字符 |
| `APP_PORT` | `8080` | 建议显式设置，方便配置域名目标端口 |
| `MIJIA_DATA_DIR` | `/data` | Docker 已设置这个默认值 |

单个 Key 示例：

```json
["YOUR_RANDOM_API_KEY_1_AT_LEAST_32_CHARS"]
```

多个 Key 示例：

```json
["YOUR_RANDOM_API_KEY_1_AT_LEAST_32_CHARS", "YOUR_RANDOM_API_KEY_2_AT_LEAST_32_CHARS"]
```

Railway 变量值直接填写 JSON 数组；本地 `.env` 用外层单引号包裹，保留 JSON 内的双引号：

```dotenv
ALLOWED_API_KEYS='["YOUR_RANDOM_API_KEY_1_AT_LEAST_32_CHARS"]'
```

示例 Key 用于展示格式，实际部署请换成自己生成的随机值。服务缺少配置、数组为空、JSON 格式错误或任一 Key 不符合要求时会退出。只有 `/health` 不要求认证；数组中的任意 Key 都可使用全部米家 MCP 工具。

### 4. 添加持久化 Volume

给该服务添加一个 **Volume**，挂载路径填写 **`/data`**。

登录后凭证位于 `/data/auth.json`，可以跨服务重启、重新部署继续使用。不要将凭证放进 Git、镜像或构建变量；Volume 必须在首次扫码登录前挂载。

保持 **一个副本、一个进程**，关闭 Railway 的 **Serverless / App Sleeping**。这些设置以及 Volume 需要在 Railway 控制台配置。

米家账号、扫码登录线程和 API 状态保存在同一个进程内。HTTP 使用无状态传输，客户端重连不需要保留 MCP 会话 ID，但这不表示米家账号状态支持多实例。已有登录线程在部署中断后需要重新发起。

### 5. 开启公网域名并部署

进入 **Settings → Networking → Public Networking → Generate Domain**，目标端口为 `8080`，然后部署。

假设域名是 `https://myhome-production.up.railway.app`：

| 地址 | 用途 |
| --- | --- |
| `https://myhome-production.up.railway.app/health` | 公开健康检查，返回 `{"status":"ok"}` |
| `https://myhome-production.up.railway.app/mcp` | Streamable HTTP MCP 接口，需要 API Key |

Railway 在公网入口提供 HTTPS，容器监听 `0.0.0.0:$APP_PORT`。域名目标端口应与 `APP_PORT` 一致。

## 客户端连接与首次扫码

客户端需要支持 Streamable HTTP，并在每次请求中发送：

```http
Authorization: Bearer YOUR_API_KEY
```

这里的固定 API Key 就是 Bearer 值，不是 JWT；没有 OAuth 登录或令牌交换步骤。服务不支持把 Key 放进 URL，也不使用 `X-API-Key`。

### 使用官方 MCP Inspector

调试统一使用 [MCP Inspector](https://github.com/modelcontextprotocol/inspector) 的网页界面。本仓库不提供自写客户端，也不使用 FastMCP CLI 调试。

本地安装 **Node.js 22.19.0 或更高版本**（包含 pnpm），然后启动 Inspector：

```bash
pnpx @modelcontextprotocol/inspector@latest
```

按终端提示打开 Inspector 网页，默认端口为 `6274`。Inspector 只用于本地调试，不需要加入 Python 依赖或 Railway 镜像；连接远程服务也不需要在本地启动本仓库。

以下步骤按官方 Inspector v2 的界面说明：

1. 在服务器列表新增一个服务器，名称可填 `MijiaMCP`。
2. 传输类型选择 **HTTP / Streamable HTTP**（`http`），URL 填完整接口地址，例如 `https://myhome-production.up.railway.app/mcp`。
3. 在该服务器的 **Server Settings → Headers** 中添加请求头：名称 `Authorization`，值 `Bearer YOUR_API_KEY`，将占位符替换成 Railway 的 `ALLOWED_API_KEYS` 数组中的任意一个 Key。注意 `Bearer` 后有一个空格，只发送单个 Key，不发送整个数组。
4. 保存并连接服务器，在 **Tools** 页面查看工具列表；当前锁定版本应提供 **14 个工具**。每个工具的参数表单由服务器返回的 schema 生成。

使用 Headers 配置固定 Key 即可，无需配置 OAuth。Inspector 自身的本地访问令牌与本服务允许的 API Key 是独立凭据。API Key 填入请求头，不放入 URL；Inspector 的服务器配置可能将 Headers 保存到本地配置文件，分享配置前删除真实 Key。

### 首次扫码与验证

在 Inspector 的 **Tools** 页面依次执行：

| 工具 | 参数 | 用途 |
| --- | --- | --- |
| `login` | `{}` | 获取二维码链接，打开后在 2 分钟内用米家 App 扫码 |
| `login_status` | `{}` | 扫码后查询登录结果；仍在等待时再次执行 |
| `list_homes` | `{}` | 登录成功后查询家庭 |
| `list_devices` | `{}` | 查询设备，验证账号访问是否正常 |

只有 `login_status` 返回登录成功后，后续设备工具才会切换到新凭证。关闭 Inspector 不会中断 Railway 上的扫码线程。

验证访问认证时，断开连接，删除 Authorization 请求头或改成错误 Key，再连接应返回 **401**，无法列出或调用工具。恢复正确请求头后重新连接。`/health` 是公开健康检查，不能用它验证 API Key。

最后重启 Railway 服务，在 Inspector 中重新连接并执行 `list_homes` 或 `list_devices`，确认 Volume 中的凭证可以继续使用。凭证失效且自动刷新失败时，重新执行 `login` 和 `login_status`。

上面的验证步骤只涉及登录和读取。Inspector 同时可以调用设备写入、动作和场景工具；执行这些工具会实际控制设备。

其他客户端填写同一 URL 和 Authorization 请求头即可。**能配置固定 Bearer 请求头的客户端才适用此方案**；它不自动提供 ChatGPT 网页/App 的 OAuth 连接流程。使用模型 API 自行开发 Agent 时，可在 MCP 客户端中配置该请求头。

## 本地开发

直接运行仓库中的 `local_run.sh`，它会自动完成环境检查、复制 `.env` 模板、同步依赖并启动服务：

```bash
./local_run.sh
```

首次运行时若缺少 `.env`，脚本会从 `.env.example` 复制一份并提示填写 `ALLOWED_API_KEYS`，编辑完成后再次执行即可启动。

另开终端启动 Inspector，按上文配置连接；本地 URL 使用 `http://127.0.0.1:8080/mcp`，Authorization 请求头使用本地 `.env` 的 `ALLOWED_API_KEYS` 数组中的一个 Key。Railway 连接使用公网 HTTPS 地址。

测试和静态检查：

```bash
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
```

测试使用真实 FastMCP HTTP 协议和上游工具定义，只替换米家云交互，覆盖访问认证、工具发现、扫码线程跨请求保留和凭证重载。测试不需要真实米家账号，不控制家中设备。测试和部署使用同一份 uv 锁文件。

构建容器：

```bash
docker build -t myhome-mijia .
docker run --rm -p 8080:8080 --env-file .env \
  -e MIJIA_DATA_DIR=/data \
  -v myhome-mijia-data:/data myhome-mijia
```

升级依赖时修改 `pyproject.toml`，执行 `uv lock`、`uv sync --locked` 并重新测试。部署适配器会暂时抑制上游 `run()` 的 stdio 启动，再挂载原有工具；升级 `mijiaAPI` 后必须核对该初始化入口。

## 运维与限制

- 轮换 Key：更新 Railway 的 `ALLOWED_API_KEYS` 并重新部署。可先加入新 Key，更新客户端后再从数组删除旧 Key；删除的 Key 随服务重启失效，米家 Volume 不需要重建。
- `/health` 成功代表 HTTP 进程可用，不代表米家已登录、设备在线或米家云可访问。首次未登录时的凭证缺失提示正常。
- 本服务连接米家云。仅支持家庭局域网或直接蓝牙连接的能力，无法通过 Railway 直接访问。米家云可能对云服务器地区、IP 或登录施加限制，需要实际扫码验证。
- 所有允许的 Key 共用这个实例保存的米家账号，权限相同；这是多个访问凭据，不提供不同账号或权限隔离。

## 参考与许可证

- [米家 MCP 文档](https://mijia-api.do1e.com/usage/mcp)
- [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
- [Inspector 服务器配置](https://github.com/modelcontextprotocol/inspector/blob/main/docs/mcp-server-configuration.md)
- [上游源码](https://github.com/Do1e/mijia-api/blob/main/mijiaAPI/mcp_server.py)
- [FastMCP TokenVerifier](https://gofastmcp.com/servers/auth/token-verification)
- [Railway 配置文件](https://docs.railway.com/config-as-code/reference)
- [Railway Volume](https://docs.railway.com/volumes)
- [uv Docker 集成](https://docs.astral.sh/uv/guides/integration/docker/)

项目许可证标注为 GPL-3.0-or-later。米家能力来自 Do1e 的 `mijiaAPI` 项目（GPL-3.0-or-later）；通过 PyPI 安装，上游许可证见其仓库。
