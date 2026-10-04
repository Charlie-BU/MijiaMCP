from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from threading import Event

import pytest
from test_server import TEST_KEYS, http_client, rpc

import server
from list_cache import LIST_TOOLS, ListCache
from server import Settings


class FakeAPI:
    available = True

    def __init__(self, user_id="test-owner"):
        self.auth_data = {"userId": user_id}
        self.revision = 1
        self.entered = Event()
        self.release = Event()
        self.release.set()
        self.calls = []
        self.failure = False
        self.empty = False

    def response(self, name, home_id=None):
        self.calls.append((name, home_id))
        self.entered.set()
        if not self.release.wait(5):
            raise RuntimeError("Test request timed out")
        if self.failure:
            raise RuntimeError("Synthetic network failure")
        if self.empty:
            return []
        if name == "homes":
            return [
                {
                    "id": "a",
                    "name": "Home A",
                    "revision": self.revision,
                    "roomlist": [{"name": "Living room", "dids": ["device-a"]}],
                }
            ]
        if name in {"devices", "shared"}:
            return [
                {
                    "did": "device-a" if name == "devices" else "shared-device",
                    "name": "Device",
                    "model": "example.model",
                    "revision": self.revision,
                    "home_id": "a" if name == "devices" else "shared",
                }
            ]
        return [
            {"home_id": home, "revision": self.revision}
            for home in ([home_id] if home_id is not None else ["a", "b"])
        ]

    def get_homes_list(self):
        return self.response("homes")

    def get_devices_list(self):
        return self.response("devices")

    def get_shared_devices_list(self):
        return self.response("shared")

    def get_scenes_list(self, home_id=None):
        return self.response("scenes", home_id)

    def get_consumable_items(self, home_id=None):
        return self.response("consumables", home_id)


@pytest.fixture
def fake_api(monkeypatch):
    api = FakeAPI()
    # Avoid real account initialization; exercise real MCP routing and authentication.
    monkeypatch.setattr(server.upstream, "run", lambda path: None)
    monkeypatch.setattr(server.upstream, "_api", api)
    yield api
    api.release.set()


@pytest.fixture
def written(monkeypatch):
    event = Event()
    original = ListCache._write

    def write(cache, *args):
        original(cache, *args)
        event.set()

    monkeypatch.setattr(ListCache, "_write", write)
    return event


async def tool_result(client, name, **arguments):
    response = await rpc(client, "tools/call", {"name": name, "arguments": arguments})
    assert response.status_code == 200
    result = response.json()["result"]
    assert not result.get("isError")
    assert len(result["content"]) == 1
    return json.loads(result["structuredContent"]["result"])


@pytest.mark.parametrize("name", sorted(LIST_TOOLS))
async def test_mcp_cached_response_does_not_wait_for_refresh_and_next_call_sees_update(
    tmp_path,
    fake_api,
    written,
    name,
):
    async with http_client(Settings(TEST_KEYS, tmp_path)) as client:
        first = await tool_result(client, name)
        path = tmp_path / f"{name}.json"
        assert json.loads(path.read_text())["results"]["null"] == first
        assert path.stat().st_mode & 0o777 == 0o600
        assert {p.name for p in tmp_path.glob("list_*.json")} == {f"{name}.json"}

        written.clear()
        fake_api.revision = 2
        fake_api.entered.clear()
        fake_api.release.clear()
        try:
            cached = await asyncio.wait_for(tool_result(client, name), timeout=1)
            assert cached == first
            assert await asyncio.to_thread(fake_api.entered.wait, 2)
            # Concurrent cache hits share the blocked refresh rather than fan out.
            count = len(fake_api.calls)
            for _ in range(3):
                assert await tool_result(client, name) == first
            assert len(fake_api.calls) == count
            assert json.loads(path.read_text())["results"]["null"] == first
        finally:
            fake_api.release.set()
        assert await asyncio.to_thread(written.wait, 2)
        latest = await tool_result(client, name)
        assert latest[0]["revision"] == 2
        if name == "list_devices":
            assert latest[0]["home"] == "Home A"
            assert latest[0]["room"] == "Living room"
            assert latest[1]["home_id"] == "shared"


@pytest.mark.parametrize("name", ["list_devices", "list_scenes", "list_consumables"])
async def test_home_filters_have_separate_entries_in_one_file(tmp_path, fake_api, name):
    cache = ListCache(tmp_path)
    try:
        responses = await asyncio.gather(
            *(asyncio.to_thread(cache.get, name, home) for home in [None, "a", "b"])
        )
        all_items, home_a, home_b = map(json.loads, responses)
        assert all(item["home_id"] == "a" for item in home_a)
        assert all(item["home_id"] == "b" for item in home_b)
        assert home_a != all_items
        stored = json.loads((tmp_path / f"{name}.json").read_text())["results"]
        assert stored == {"null": all_items, '"a"': home_a, '"b"': home_b}
        assert len(list(tmp_path.glob("*.json"))) == 1
    finally:
        cache.close()


async def test_concurrent_cold_requests_share_one_network_query(tmp_path, fake_api, monkeypatch):
    cache = ListCache(tmp_path)
    fake_api.release.clear()
    all_read = Event()
    reads = 0
    original = cache._read

    def read(*args):
        nonlocal reads
        reads += 1
        if reads == 5:
            all_read.set()
        return original(*args)

    monkeypatch.setattr(cache, "_read", read)
    requests = [asyncio.create_task(asyncio.to_thread(cache.get, "list_scenes")) for _ in range(5)]
    try:
        assert await asyncio.to_thread(all_read.wait, 2)
        assert not any(request.done() for request in requests)
        fake_api.release.set()
        results = await asyncio.gather(*requests)
        assert len(set(results)) == 1
        assert fake_api.calls == [("scenes", None)]
    finally:
        fake_api.release.set()
        cache.close()


async def test_unchanged_refresh_still_updates_file(tmp_path, fake_api, written):
    cache = ListCache(tmp_path)
    initial = await asyncio.to_thread(cache.get, "list_homes")
    written.clear()
    try:
        assert await asyncio.to_thread(cache.get, "list_homes") == initial
        assert await asyncio.to_thread(written.wait, 2)
        assert fake_api.calls == [("homes", None), ("homes", None)]
        assert json.loads((tmp_path / "list_homes.json").read_text())["results"]["null"] == (
            json.loads(initial)
        )
    finally:
        cache.close()


async def test_refresh_failure_retains_cache_and_cold_failure_is_an_error(
    tmp_path,
    fake_api,
    monkeypatch,
):
    cache = ListCache(tmp_path)
    initial = await asyncio.to_thread(cache.get, "list_scenes")
    path = tmp_path / "list_scenes.json"
    before = path.read_bytes()
    completed = Event()
    original = cache._refresh

    def refresh(*args):
        try:
            original(*args)
        finally:
            completed.set()

    monkeypatch.setattr(cache, "_refresh", refresh)
    fake_api.failure = True
    try:
        assert await asyncio.to_thread(cache.get, "list_scenes") == initial
        assert await asyncio.to_thread(completed.wait, 2)
        assert path.read_bytes() == before
        with pytest.raises(RuntimeError, match="Synthetic network failure"):
            await asyncio.to_thread(cache.get, "list_consumables")
        assert not (tmp_path / "list_consumables.json").exists()
    finally:
        cache.close()


@pytest.mark.parametrize("contents", ["{", "[]", '{"version":1}', "\xff"])
async def test_invalid_cache_is_replaced_from_network(tmp_path, fake_api, contents):
    path = tmp_path / "list_homes.json"
    path.write_bytes(contents.encode("latin-1"))
    cache = ListCache(tmp_path)
    try:
        assert json.loads(await asyncio.to_thread(cache.get, "list_homes"))[0]["revision"] == 1
        assert json.loads(path.read_text())["version"] == 1
    finally:
        cache.close()


async def test_empty_lists_are_cache_hits_and_files_survive_restart(tmp_path, fake_api):
    fake_api.empty = True
    cache = ListCache(tmp_path)
    assert await asyncio.to_thread(cache.get, "list_homes") == "[]"
    cache.close()
    restarted = ListCache(tmp_path)
    fake_api.release.clear()
    try:
        assert await asyncio.wait_for(asyncio.to_thread(restarted.get, "list_homes"), 1) == "[]"
    finally:
        restarted.close()
        fake_api.release.set()


async def test_account_switch_does_not_serve_or_overwrite_another_accounts_cache(
    tmp_path,
    fake_api,
    monkeypatch,
):
    cache = ListCache(tmp_path)
    await asyncio.to_thread(cache.get, "list_scenes")
    fake_api.entered.clear()
    fake_api.release.clear()
    completed = Event()
    original = cache._refresh

    def refresh(*args):
        try:
            original(*args)
        finally:
            completed.set()

    monkeypatch.setattr(cache, "_refresh", refresh)
    await asyncio.to_thread(cache.get, "list_scenes")
    assert await asyncio.to_thread(fake_api.entered.wait, 2)
    new_api = FakeAPI("different-owner")
    new_api.revision = 10
    monkeypatch.setattr(server.upstream, "_api", new_api)
    other_cache = ListCache(tmp_path)
    try:
        other = asyncio.create_task(asyncio.to_thread(other_cache.get, "list_scenes"))
        result = json.loads(await asyncio.wait_for(other, 2))
        assert result[0]["revision"] == 10
        before = (tmp_path / "list_scenes.json").read_bytes()
        fake_api.release.set()
        assert await asyncio.to_thread(completed.wait, 2)
        assert (tmp_path / "list_scenes.json").read_bytes() == before
    finally:
        cache.close()
        other_cache.close()
        fake_api.release.set()


async def test_shutdown_discards_pending_refresh(tmp_path, fake_api, monkeypatch):
    cache = ListCache(tmp_path)
    await asyncio.to_thread(cache.get, "list_homes")
    path = tmp_path / "list_homes.json"
    before = path.read_bytes()
    finished = Event()
    original = cache._refresh

    def refresh(*args):
        try:
            original(*args)
        finally:
            finished.set()

    monkeypatch.setattr(cache, "_refresh", refresh)
    fake_api.revision = 2
    fake_api.entered.clear()
    fake_api.release.clear()
    await asyncio.to_thread(cache.get, "list_homes")
    assert await asyncio.to_thread(fake_api.entered.wait, 2)
    cache.close()
    fake_api.release.set()
    assert await asyncio.to_thread(finished.wait, 2)
    assert path.read_bytes() == before


async def test_tools_keep_original_schemas_and_have_no_duplicates(tmp_path, fake_api):
    originals = {tool.name: tool.parameters for tool in await server.upstream.mcp.list_tools()}
    async with http_client(Settings(TEST_KEYS, tmp_path)) as client:
        response = await rpc(client, "tools/list")
        tools = response.json()["result"]["tools"]
        assert len(tools) == 14
        assert len({tool["name"] for tool in tools}) == 14
        for tool in tools:
            if tool["name"] in LIST_TOOLS:
                assert tool["inputSchema"] == originals[tool["name"]]


async def test_cache_is_not_available_without_xiaomi_login(tmp_path, fake_api, monkeypatch):
    cache = ListCache(tmp_path)
    await asyncio.to_thread(cache.get, "list_homes")
    monkeypatch.setattr(server.upstream, "_api", None)
    try:
        with pytest.raises(RuntimeError, match="未初始化"):
            cache.get("list_homes")
    finally:
        cache.close()


async def test_failed_atomic_replace_keeps_previous_json(tmp_path, fake_api, monkeypatch):
    cache = ListCache(tmp_path)
    await asyncio.to_thread(cache.get, "list_homes")
    path = tmp_path / "list_homes.json"
    before = deepcopy(json.loads(path.read_text()))

    def fail_replace(*args):
        raise OSError("Synthetic disk failure")

    monkeypatch.setattr("list_cache.os.replace", fail_replace)
    try:
        with cache._lock:
            with pytest.raises(OSError):
                cache._write("list_homes", cache._account(fake_api), "null", [])
        assert json.loads(path.read_text()) == before
        assert not list(tmp_path.glob("*.tmp"))
    finally:
        cache.close()
