from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Event

import httpx
import pytest

import server
from server import APIKeyVerifier, Settings, create_server

TEST_KEY = "test-only-key-" + "a" * 32
SECOND_KEY = "test-only-key-" + "b" * 32
TEST_KEYS = (TEST_KEY, SECOND_KEY)
HEADERS = {
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-03-26",
}


@pytest.fixture(autouse=True)
def reset_upstream(monkeypatch):
    """重置米家模块状态，隔离各项测试的账号和登录线程。"""
    for name in ("_api", "_auth_path", "_login_api", "_login_data", "_login_thread"):
        monkeypatch.setattr(server.upstream, name, None)
    monkeypatch.setattr(server.upstream, "_login_status", {"status": "idle"})


@asynccontextmanager
async def http_client(settings):
    """创建具有完整生命周期的内存 HTTP 测试客户端。"""
    app = create_server(settings).http_app(path="/mcp", stateless_http=True, json_response=True)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://localhost"
        ) as client:
            yield client


async def rpc(client, method, params=None, authorization=f"Bearer {TEST_KEY}"):
    """向测试服务发送带可选认证的 MCP 请求。"""
    headers = dict(HEADERS)
    if authorization is not None:
        headers["Authorization"] = authorization
    return await client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
    )


@pytest.mark.parametrize(
    "raw_keys",
    [
        None,
        "",
        "[",
        "[]",
        "null",
        "{}",
        json.dumps(TEST_KEY),
        json.dumps([""]),
        json.dumps(["short"]),
        json.dumps(["x" * 32 + " "]),
        json.dumps(["密" * 32]),
        json.dumps([None]),
        json.dumps([42]),
        json.dumps([TEST_KEY, "short"]),
    ],
)
def test_startup_rejects_missing_or_invalid_keys_without_echoing_them(raw_keys):
    """验证缺失或无效密钥数组被拒绝且错误不泄漏配置内容。"""
    env = {} if raw_keys is None else {"ALLOWED_API_KEYS": raw_keys}
    with pytest.raises(ValueError, match="ALLOWED_API_KEYS") as error:
        Settings.from_env(env)
    if raw_keys:
        assert raw_keys not in str(error.value)
    assert TEST_KEY not in str(error.value)


@pytest.mark.parametrize("port", ["nope", "0", "65536"])
def test_invalid_port_is_rejected(port):
    """验证非法监听端口无法通过配置校验。"""
    with pytest.raises(ValueError, match="APP_PORT"):
        Settings.from_env({"ALLOWED_API_KEYS": json.dumps(TEST_KEYS), "APP_PORT": port})


async def test_verifier_and_settings_do_not_expose_plaintext_key():
    """验证密钥认证有效且对象表示不泄漏明文密钥。"""
    verifier = APIKeyVerifier(TEST_KEYS)
    for key in TEST_KEYS:
        assert key not in repr(Settings(TEST_KEYS))
        assert key not in repr(vars(verifier))
        assert (await verifier.verify_token(key)).client_id == "myhome-owner"
    assert await verifier.verify_token("wrong") is None
    assert await verifier.verify_token(TEST_KEY + "extra") is None


@pytest.mark.parametrize("authorization", [None, "Bearer wrong", f"Basic {TEST_KEY}"])
async def test_all_mcp_requests_require_correct_bearer_key(tmp_path, authorization):
    """验证未授权请求无法初始化会话、发现工具或发起登录。"""
    async with http_client(Settings(TEST_KEYS, tmp_path)) as client:
        for method, params in [
            (
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            ),
            ("tools/list", {}),
            ("tools/call", {"name": "login", "arguments": {}}),
        ]:
            response = await rpc(client, method, params, authorization)
            assert response.status_code == 401
            assert TEST_KEY not in response.text
        assert server.upstream._login_thread is None


@pytest.mark.parametrize("keys", [(TEST_KEY,), TEST_KEYS])
async def test_health_and_real_upstream_tools_are_available_before_xiaomi_login(tmp_path, keys):
    """验证未登录时健康检查和工具发现可用，设备查询被拒绝。"""
    settings = Settings.from_env(
        {
            "ALLOWED_API_KEYS": json.dumps(keys),
            "MIJIA_DATA_DIR": str(tmp_path),
        }
    )
    async with http_client(settings) as client:
        health = await client.get("/health")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}

        for key in keys:
            response = await rpc(client, "tools/list", authorization=f"Bearer {key}")
            assert response.status_code == 200
            denied = await rpc(client, "tools/list", authorization=f"Bearer {key}extra")
            assert denied.status_code == 401
            response = await rpc(
                client,
                "tools/call",
                {"name": "list_homes", "arguments": {}},
                authorization=f"Bearer {key}",
            )
            assert response.status_code == 200
            assert response.json()["result"]["isError"] is True
        response = await rpc(client, "tools/list")
        assert response.status_code == 200
        tools = {tool["name"]: tool for tool in response.json()["result"]["tools"]}
        assert tools.keys() == {
            "login",
            "login_status",
            "list_homes",
            "list_devices",
            "list_scenes",
            "list_consumables",
            "get_device_spec",
            "get_device_properties",
            "set_device_property",
            "run_device_action",
            "run_scene",
            "get_statistics",
            "run_speaker_command",
            "speaker_play",
        }
        assert tools["set_device_property"]["inputSchema"]["properties"]

        response = await rpc(client, "tools/call", {"name": "list_homes", "arguments": {}})
        assert response.json()["result"]["isError"] is True
        assert not (tmp_path / "auth.json").exists()


async def test_qr_login_survives_separate_http_requests_and_credentials_reload(
    tmp_path, monkeypatch
):
    """验证扫码状态跨请求保留，保存的凭证可在重启后重载。"""
    allow_scan = Event()
    persisted = Event()

    class FakeXiaomiAPI:
        def __init__(self, auth_data_path: Path):
            """根据测试凭证文件模拟米家登录状态。"""
            self.path = auth_data_path
            self.available = auth_data_path.exists()

        def _get_qr_login_data(self):
            """返回测试用二维码链接。"""
            return {"qr": "https://example.invalid/test-qr"}

        def _complete_qr_login(self, login_data):
            """等待模拟扫码并保存测试凭证。"""
            if not allow_scan.wait(5):
                raise RuntimeError("Test scan timed out")
            self.path.write_text(json.dumps({"test_only": True}))
            self.available = True
            persisted.set()

        def get_homes_list(self):
            """返回固定的测试家庭信息。"""
            return [{"id": "test-home", "name": "Test Home"}]

    monkeypatch.setattr(server.upstream, "mijiaAPI", FakeXiaomiAPI)
    settings = Settings(TEST_KEYS, tmp_path)
    try:
        async with http_client(settings) as client:
            response = await rpc(client, "tools/call", {"name": "login", "arguments": {}})
            assert "test-qr" in response.text

            response = await rpc(client, "tools/call", {"name": "login_status", "arguments": {}})
            assert "等待扫码" in response.json()["result"]["content"][0]["text"]

            allow_scan.set()
            assert await asyncio.to_thread(persisted.wait, 5)
            await asyncio.to_thread(server.upstream._login_thread.join, 5)
            response = await rpc(client, "tools/call", {"name": "login_status", "arguments": {}})
            assert "登录成功" in response.json()["result"]["content"][0]["text"]
            response = await rpc(client, "tools/call", {"name": "list_homes", "arguments": {}})
            assert "test-home" in response.text

        # 模拟重新部署时从持久化文件恢复账号。
        async with http_client(settings) as client:
            response = await rpc(client, "tools/call", {"name": "list_homes", "arguments": {}})
            assert "test-home" in response.text
        assert (tmp_path / "auth.json").stat().st_mode & 0o777 == 0o600
    finally:
        allow_scan.set()


def test_adapter_restores_upstream_start_method_on_failure(tmp_path, monkeypatch):
    """验证初始化异常时仍会恢复上游原始启动方法。"""
    original = server.upstream.mcp.run

    def fail(auth_path):
        """模拟上游凭证初始化失败。"""
        raise RuntimeError("Initialization failed")

    monkeypatch.setattr(server.upstream, "run", fail)
    with pytest.raises(RuntimeError, match="Initialization failed"):
        create_server(Settings(TEST_KEYS, tmp_path))
    assert server.upstream.mcp.run == original
