"""通过固定 API Key 提供米家 HTTP MCP 服务。"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import mijiaAPI.mcp_server as upstream
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, MultiAuth, TokenVerifier
from fastmcp.server.providers.fastmcp_provider import FastMCPProvider
from fastmcp.server.transforms import Visibility
from starlette.requests import Request
from starlette.responses import JSONResponse

from list_cache import LIST_TOOLS, ListCache, register_list_tools
from oauth import SCOPE, OwnerOAuthProvider

# 本地加载 .env，部署平台已设置的环境变量优先。
load_dotenv(override=False)


@dataclass(frozen=True)
class Settings:
    """保存服务认证、存储目录和监听端口配置。"""

    # 以下均为默认值，实际启动时从环境变量加载
    allowed_api_keys: tuple[str, ...] = field(repr=False)
    data_dir: Path = Path("./.data")
    port: int = 8080
    public_url: str | None = None
    access_token_expire_seconds: int = 2592000

    def __post_init__(self) -> None:
        """校验 API Key 和端口，阻止无效配置启动服务。"""
        if not isinstance(self.allowed_api_keys, tuple) or not self.allowed_api_keys:
            raise ValueError("ALLOWED_API_KEYS must be a non-empty JSON array of strings")
        for key in self.allowed_api_keys:
            if (
                not isinstance(key, str)
                or len(key) < 32
                or any(not 33 <= ord(char) <= 126 for char in key)
            ):
                raise ValueError(
                    "ALLOWED_API_KEYS entries must contain at least 32 ASCII non-space characters"
                )
        if not 1 <= self.port <= 65535:
            raise ValueError("APP_PORT must be an integer between 1 and 65535")

        if (
            type(self.access_token_expire_seconds) is not int
            or self.access_token_expire_seconds == 0
            or self.access_token_expire_seconds < -1
        ):
            raise ValueError("ACCESS_TOKEN_EXPIRE_SECONDS must be -1 or a positive integer")

    @classmethod
    def from_env(cls) -> Settings:
        """从环境变量读取服务配置。"""
        try:
            keys = json.loads(os.getenv("ALLOWED_API_KEYS", ""))
        except json.JSONDecodeError:
            raise ValueError("ALLOWED_API_KEYS must be a non-empty JSON array of strings") from None
        if not isinstance(keys, list):
            raise ValueError("ALLOWED_API_KEYS must be a non-empty JSON array of strings")
        try:
            port = int(os.getenv("APP_PORT", "8080"))
        except ValueError:
            raise ValueError("APP_PORT must be an integer between 1 and 65535") from None
        try:
            token_expiry = int(os.getenv("ACCESS_TOKEN_EXPIRE_SECONDS", "2592000"))
        except ValueError:
            raise ValueError(
                "ACCESS_TOKEN_EXPIRE_SECONDS must be -1 or a positive integer"
            ) from None
        # Railway specific
        # 确保数据目录在持久卷内
        volume_path = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
        data_dir = Path(os.getenv("MIJIA_DATA_DIR") or volume_path or "./.data")
        if os.getenv("RAILWAY_ENVIRONMENT_ID"):
            if not volume_path:
                raise ValueError("Railway requires a persistent volume for Mijia and OAuth state")
            if not data_dir.resolve().is_relative_to(Path(volume_path).resolve()):
                raise ValueError("MIJIA_DATA_DIR must be inside the Railway persistent volume")
        return cls(
            allowed_api_keys=tuple(keys),
            data_dir=data_dir,
            port=port,
            access_token_expire_seconds=token_expiry,
            public_url=os.getenv("MIJIA_PUBLIC_URL")
            or (
                "https://" + os.getenv("RAILWAY_PUBLIC_DOMAIN", "")
                if os.getenv("RAILWAY_PUBLIC_DOMAIN")
                else None
            ),
        )


class APIKeyVerifier(TokenVerifier):
    """校验客户端提交的固定 Bearer 密钥。"""

    def __init__(self, allowed_api_keys: tuple[str, ...]):
        """保存所有允许密钥的摘要以供后续认证比较。"""
        super().__init__()
        self._key_digests = tuple(
            hashlib.sha256(key.encode("utf-8")).digest() for key in allowed_api_keys
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        """恒定时间比较密钥摘要，并返回认证结果。"""
        candidate = hashlib.sha256(token.encode("utf-8")).digest()
        matched = False
        for digest in self._key_digests:
            matched |= hmac.compare_digest(candidate, digest)
        if not matched:
            return None
        return AccessToken(
            token=token,
            client_id="myhome-owner",
            subject="myhome-owner",
            scopes=[SCOPE],
        )


def _skip_stdio(**kwargs) -> None:
    """跳过上游 stdio 启动，以复用其凭证初始化逻辑。"""


def create_server(settings: Settings) -> FastMCP:
    """初始化米家凭证，挂载受密钥保护的工具及健康检查。"""
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    auth_path = settings.data_dir / "auth.json"
    if auth_path.exists():
        auth_path.chmod(0o600)

    # 上游没有独立初始化入口，暂时跳过 stdio 启动，完成后恢复原方法。
    original_run = upstream.mcp.run
    upstream.mcp.run = _skip_stdio
    try:
        upstream.run(auth_path)
    finally:
        upstream.mcp.run = original_run

    verifier = APIKeyVerifier(settings.allowed_api_keys)
    auth = verifier
    if settings.public_url:
        auth = MultiAuth(
            server=OwnerOAuthProvider(
                settings.public_url,
                settings.data_dir,
                settings.allowed_api_keys,
                access_token_expire_seconds=settings.access_token_expire_seconds,
            ),
            verifiers=[verifier],
        )
    cache = ListCache(settings.data_dir)

    @asynccontextmanager
    async def lifespan(server):
        try:
            yield
        finally:
            cache.close()

    server = FastMCP("MyHome Mijia", auth=auth, lifespan=lifespan)
    # Hide upstream list tools only on this mount, avoiding duplicate tool names
    # without changing the shared upstream server or its device-control tools.
    provider = FastMCPProvider(upstream.mcp).wrap_transform(
        Visibility(False, names=LIST_TOOLS, components={"tool"})
    )
    server.add_provider(provider)
    register_list_tools(server, cache)

    @server.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        """返回进程健康状态，供 Railway 检查服务是否启动。"""
        return JSONResponse({"status": "ok"})

    return server


def main() -> None:
    """限制凭证文件权限并启动 HTTP MCP 服务。"""
    os.umask(0o077)
    try:
        settings = Settings.from_env()
    except ValueError as error:
        raise SystemExit(str(error)) from None

    server = create_server(settings)
    server.run(
        transport="http",
        host="0.0.0.0",
        port=settings.port,
        path="/mcp",
        stateless_http=True,
        json_response=True,
        show_banner=False,
        log_level="INFO",
    )


if __name__ == "__main__":
    main()
