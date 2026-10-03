"""Local-only consent regression probe. Uses synthetic credentials, never device data."""

import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlencode

import httpx
import uvicorn
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from server import Settings, create_server  # noqa: E402

BASE = "http://localhost:8927"
CALLBACK = "http://127.0.0.1:8927/callback"
KEY = "browser-test-only-" + "a" * 32
VERIFIER = "v" * 64
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
)
state = {}


async def start(request):
    async with httpx.AsyncClient() as client:
        result = await client.post(
            BASE + "/register",
            json={
                "redirect_uris": [CALLBACK],
                "client_name": "Browser regression test",
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "mijia",
            },
        )
        result.raise_for_status()
        state["client_id"] = result.json()["client_id"]
    return RedirectResponse(
        BASE
        + "/authorize?"
        + urlencode(
            {
                "client_id": state["client_id"],
                "redirect_uri": CALLBACK,
                "response_type": "code",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "scope": "mijia",
                "state": "browser-test",
                "resource": BASE + "/mcp",
            }
        )
    )


async def callback(request):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            BASE + "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": state["client_id"],
                "code": request.query_params.get("code", ""),
                "code_verifier": VERIFIER,
                "redirect_uri": CALLBACK,
                "resource": BASE + "/mcp",
            },
        )
        if response.status_code != 200:
            return HTMLResponse("Token exchange failed", status_code=500)
        result = await client.post(
            BASE + "/mcp",
            headers={
                "Authorization": "Bearer " + response.json()["access_token"],
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        count = len(result.json()["result"]["tools"])
    return HTMLResponse(
        "<h1>Browser OAuth passed</h1><p>Cross-origin callback, PKCE token exchange "
        f"and MCP discovery succeeded: {count} tools.</p>"
    )


temporary = tempfile.TemporaryDirectory(prefix="mijia-browser-probe-")
app = create_server(Settings((KEY,), Path(temporary.name), public_url=BASE)).http_app(
    path="/mcp",
    stateless_http=True,
    json_response=True,
)
app.routes.extend([Route("/start", start), Route("/callback", callback)])


class Diagnostic:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def capture(message):
            if scope.get("path") == "/oauth/consent" and message["type"] == "http.response.start":
                headers = dict(scope["headers"])
                print(
                    json.dumps(
                        {
                            "method": scope["method"],
                            "origin": headers.get(b"origin", b"").decode(),
                            "cookie_present": b"cookie" in headers,
                            "status": message["status"],
                        }
                    ),
                    flush=True,
                )
            await send(message)

        await self.app(scope, receive, capture)


if __name__ == "__main__":
    print(f"Open {BASE}/start; synthetic API Key: {KEY}", flush=True)
    uvicorn.run(Diagnostic(app), host="127.0.0.1", port=8927, access_log=False)
