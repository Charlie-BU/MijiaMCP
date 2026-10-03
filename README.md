# MijiaMCP

基于 [mijiaAPI](https://github.com/Do1e/mijia-api) 提供米家 Streamable HTTP MCP 服务，支持通过 Agent 查询和控制设备，使用 API Key 认证、uv 管理 Python 依赖。

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

客户端需支持 Streamable HTTP，并在每次请求中携带：

```http
Authorization: Bearer YOUR_API_KEY
```

只发送数组中的一个 Key，无需 OAuth。未提供或不匹配会返回 **401**；`/health` 无需认证。

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
