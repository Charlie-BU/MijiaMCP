"""File-backed list queries with stale results and silent background refreshes."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from concurrent.futures import Future
from pathlib import Path
from threading import Lock, Thread

import mijiaAPI.mcp_server as upstream
from fastmcp import FastMCP

logger = logging.getLogger(__name__)
LIST_TOOLS = {"list_homes", "list_devices", "list_scenes", "list_consumables"}


class ListCache:
    """Keep one JSON file per tool, with separate entries for each home_id."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._lock = Lock()
        # The upstream API shares a requests Session and mutable login state.
        self._fetch_lock = Lock()
        self._pending: dict[tuple[str, str, str], Future] = {}
        self._closed = False

    @staticmethod
    def _account(api) -> str:
        user_id = api.auth_data.get("userId")
        if user_id is None:
            raise RuntimeError("米家账号尚未登录，请先调用 login 工具完成登录")
        return hashlib.sha256(str(user_id).encode()).hexdigest()

    def _read(self, name: str, account: str) -> dict:
        try:
            record = json.loads((self.data_dir / f"{name}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if (
            not isinstance(record, dict)
            or record.get("version") != 1
            or record.get("account") != account
            or not isinstance(record.get("results"), dict)
        ):
            return {}
        return {key: value for key, value in record["results"].items() if isinstance(value, list)}

    def _write(self, name: str, account: str, query: str, result: list) -> None:
        # Caller holds _lock: merge query variants and atomically replace the file.
        results = self._read(name, account)
        results[query] = result
        record = {"version": 1, "account": account, "results": results}
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.data_dir,
                prefix=f".{name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                json.dump(record, temporary, ensure_ascii=False, indent=2)
            os.replace(temporary_path, self.data_dir / f"{name}.json")
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _fetch(api, name: str, home_id: str | None) -> list:
        upstream._refresh_if_needed(api)
        if name == "list_homes":
            return api.get_homes_list()
        if name == "list_scenes":
            return api.get_scenes_list(home_id)
        if name == "list_consumables":
            return api.get_consumable_items(home_id)

        # Preserve upstream list_devices output, including shared devices and locations.
        devices = api.get_devices_list() + api.get_shared_devices_list()
        locations = {}
        for home in api.get_homes_list():
            for room in home.get("roomlist", []):
                for did in room.get("dids", []) or []:
                    locations[did] = (home["name"], room["name"])
        for device in devices:
            device["home"], device["room"] = locations.get(device["did"], ("未知", "未知"))
        return devices if home_id is None else [d for d in devices if d.get("home_id") == home_id]

    def _refresh(self, api, name, home_id, account, query, future) -> None:
        key = (name, account, query)
        try:
            with self._fetch_lock:
                with self._lock:
                    if self._closed or upstream._api is not api:
                        raise RuntimeError("米家登录状态已变化，请重新查询")
                result = self._fetch(api, name, home_id)
            if not isinstance(result, list):
                raise ValueError("Mijia list query returned an invalid result")
            with self._lock:
                if not self._closed and upstream._api is api and self._account(api) == account:
                    try:
                        self._write(name, account, query, result)
                    except (OSError, ValueError) as error:
                        logger.warning("Unable to save %s cache (%s)", name, type(error).__name__)
            future.set_result(result)
        except Exception as error:
            # Server log only; never send a second MCP response or notification.
            logger.warning(
                "Refresh failed for %s (%s); retaining cache", name, type(error).__name__
            )
            future.set_exception(error)
        finally:
            with self._lock:
                self._pending.pop(key, None)

    def get(self, name: str, home_id: str | None = None) -> str:
        api = upstream._get_api()
        account = self._account(api)
        query = json.dumps(home_id)
        key = (name, account, query)
        with self._lock:
            if self._closed:
                raise RuntimeError("Mijia server is shutting down")
            results = self._read(name, account)
            future = self._pending.get(key)
            if future is None:
                future = Future()
                self._pending[key] = future
                Thread(
                    target=self._refresh,
                    args=(api, name, home_id, account, query, future),
                    name=f"mijia-cache-{name}",
                    daemon=True,
                ).start()
            if query in results:
                return json.dumps(results[query], ensure_ascii=False)
        # A cache miss waits for the shared fetch; cached calls never wait for it.
        return json.dumps(future.result(), ensure_ascii=False)

    def close(self) -> None:
        with self._lock:
            self._closed = True


def register_list_tools(server: FastMCP, cache: ListCache) -> None:
    """Replace only the four list tools, keeping names, inputs and result shapes."""

    def list_homes() -> str:
        return cache.get("list_homes")

    def list_devices(home_id: str | None = None) -> str:
        return cache.get("list_devices", home_id)

    def list_scenes(home_id: str | None = None) -> str:
        return cache.get("list_scenes", home_id)

    def list_consumables(home_id: str | None = None) -> str:
        return cache.get("list_consumables", home_id)

    for function in (list_homes, list_devices, list_scenes, list_consumables):
        description = getattr(upstream, function.__name__).__doc__ or ""
        server.tool(
            function,
            description=description + "\n优先返回本地缓存；后台静默刷新，缓存可能不是最新状态。",
        )
