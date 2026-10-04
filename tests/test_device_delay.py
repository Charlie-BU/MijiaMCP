from __future__ import annotations

from types import SimpleNamespace

import mijiaAPI.devices as devices
import pytest
from test_server import TEST_KEYS, http_client, rpc

import server
from server import Settings


@pytest.mark.parametrize(
    ("tool", "arguments", "expected_operations"),
    [
        ("get_device_properties", {"did": "test-device"}, ["get", "get"]),
        (
            "set_device_property",
            {"did": "test-device", "prop_name": "on", "value": "true"},
            ["set"],
        ),
        (
            "run_device_action",
            {"did": "test-device", "action_name": "test-action"},
            ["action"],
        ),
        ("run_speaker_command", {"prompt": "test command"}, ["action"]),
        ("speaker_play", {"text": "test text"}, ["action"]),
    ],
)
async def test_mcp_device_tools_remove_delay_without_skipping_api_calls(
    tmp_path,
    monkeypatch,
    tool,
    arguments,
    expected_operations,
):
    operations = []
    sleeps = []

    class FakeAPI:
        available = True
        auth_data = {"userId": "test-owner"}
        auth_data_path = tmp_path / "auth.json"

        def get_devices_list(self):
            return [
                {
                    "did": "test-device",
                    "name": "Test Speaker",
                    "model": "xiaomi.wifispeaker.test",
                }
            ]

        def get_devices_prop(self, data):
            operations.append("get")
            return {"code": 0, "value": True}

        def set_devices_prop(self, data):
            operations.append("set")
            assert data["value"] is True
            return {"code": 0}

        def run_action(self, data):
            operations.append("action")
            return {"code": 0}

    spec = {
        "properties": [
            {
                "name": name,
                "description": name,
                "type": "bool",
                "rw": "rw",
                "range": None,
                "method": {"siid": 2, "piid": index},
            }
            for index, name in enumerate(["on", "muted"], 1)
        ],
        "actions": [
            {
                "name": name,
                "description": name,
                "method": {"siid": 2, "aiid": index},
            }
            for index, name in enumerate(["test-action", "execute-text-directive", "play-text"], 1)
        ],
    }
    monkeypatch.setattr(server.upstream, "run", lambda path: None)
    monkeypatch.setattr(server.upstream, "_api", FakeAPI())
    monkeypatch.setattr(server.upstream, "mijiaDevice", devices.mijiaDevice)
    monkeypatch.setattr(devices, "get_device_info", lambda *args, **kwargs: spec)
    # Replace only the device module's clock, leaving other libraries unaffected.
    monkeypatch.setattr(devices, "time", SimpleNamespace(sleep=sleeps.append))
    async with http_client(Settings(TEST_KEYS, tmp_path)) as client:
        response = await rpc(client, "tools/call", {"name": tool, "arguments": arguments})
        assert response.status_code == 200
        assert not response.json()["result"].get("isError")
    assert operations == expected_operations
    assert sleeps == [0] * len(expected_operations)
