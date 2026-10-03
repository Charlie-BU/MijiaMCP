from __future__ import annotations

import base64
import hashlib
import re
import time
from urllib.parse import parse_qs, urlparse

import pytest
from test_server import SECOND_KEY, TEST_KEY, TEST_KEYS, http_client, rpc

from oauth import OwnerOAuthProvider, digest
from server import Settings

BASE = "http://localhost"
CALLBACK = "http://127.0.0.1:9876/callback"
RESOURCE = BASE + "/mcp"
VERIFIER = "v" * 64
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
)


async def register(client, callback=CALLBACK):
    response = await client.post(
        "/register",
        json={
            "redirect_uris": [callback],
            "client_name": "Test client <script>",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "mijia",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


async def consent_page(client, client_id, **extra):
    response = await client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "response_type": "code",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "scope": "mijia",
            "state": "test-state",
            "resource": RESOURCE,
            **extra,
        },
    )
    assert response.status_code == 302, response.text
    page = await client.get(response.headers["location"])
    assert page.status_code == 200
    assert "<script>" not in page.text
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["referrer-policy"] == "same-origin"
    callback = urlparse(extra.get("redirect_uri", CALLBACK))
    assert page.headers["content-security-policy"] == (
        f"default-src 'none'; form-action 'self' {callback.scheme}://{callback.netloc}; "
        "frame-ancestors 'none'"
    )
    return {
        name: re.search(rf'name="{name}" value="([^"]+)"', page.text)[1]
        for name in ["request", "csrf"]
    }


async def grant(client, client_id):
    fields = await consent_page(client, client_id)
    response = await client.post(
        "/oauth/consent",
        data={**fields, "api_key": TEST_KEY, "decision": "allow"},
        headers={"Origin": BASE},
    )
    assert response.status_code == 302, response.text
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["state"] == ["test-state"]
    return {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": query["code"][0],
        "code_verifier": VERIFIER,
        "redirect_uri": CALLBACK,
        "resource": RESOURCE,
    }


async def test_discovery_existing_keys_and_oauth_only_after_owner_consent(tmp_path):
    async with http_client(Settings(TEST_KEYS, tmp_path, public_url=BASE)) as client:
        denied = await rpc(client, "tools/list", authorization=None)
        assert denied.status_code == 401
        assert (
            'resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp"'
            in denied.headers["www-authenticate"]
        )
        resource = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
        assert resource["resource"] == RESOURCE
        metadata = (await client.get("/.well-known/oauth-authorization-server")).json()
        assert metadata["registration_endpoint"] == BASE + "/register"
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert (await rpc(client, "tools/list")).status_code == 200
        client_id = await register(client)
        fields = await consent_page(client, client_id)
        for key, csrf, expected in [("wrong", fields["csrf"], 401), (TEST_KEY, "wrong", 403)]:
            response = await client.post(
                "/oauth/consent", data={**fields, "csrf": csrf, "api_key": key}
            )
            assert response.status_code == expected
            assert TEST_KEY not in response.text
        data = await grant(client, client_id)
        assert (
            await client.post("/token", data={**data, "resource": "https://other.invalid/mcp"})
        ).status_code == 400
        assert (
            await client.post("/token", data={**data, "code_verifier": "wrong"})
        ).status_code == 401
        token = await client.post("/token", data=data)
        assert token.status_code == 200, token.text
        token = token.json()
        tools = await rpc(client, "tools/list", authorization="Bearer " + token["access_token"])
        assert len(tools.json()["result"]["tools"]) == 14
        assert (await client.post("/token", data=data)).status_code == 401
        db = (tmp_path / "oauth.sqlite3").read_bytes()
        for secret in [
            TEST_KEY,
            SECOND_KEY,
            data["code"],
            token["access_token"],
            token["refresh_token"],
        ]:
            assert secret.encode() not in db
        assert (tmp_path / "oauth.sqlite3").stat().st_mode & 0o777 == 0o600

    # A deployment restart preserves registration and authorization, without re-login.
    async with http_client(Settings(TEST_KEYS, tmp_path, public_url=BASE)) as client:
        assert (
            await rpc(client, "tools/list", authorization="Bearer " + token["access_token"])
        ).status_code == 200
        refresh = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": token["refresh_token"],
            "resource": RESOURCE,
        }
        new = await client.post("/token", data=refresh)
        assert new.status_code == 200, new.text
        new_token = new.json()["access_token"]
        assert (
            await rpc(client, "tools/list", authorization="Bearer " + token["access_token"])
        ).status_code == 401
        assert (
            await rpc(client, "tools/list", authorization="Bearer " + new_token)
        ).status_code == 200
        assert (await client.post("/token", data=refresh)).status_code == 401
        # Refresh replay revokes the whole grant.
        assert (
            await rpc(client, "tools/list", authorization="Bearer " + new_token)
        ).status_code == 401


async def test_expiry_wrong_client_callback_resource_and_key_rotation(tmp_path):
    settings = Settings(TEST_KEYS, tmp_path, public_url=BASE)
    async with http_client(settings) as client:
        client_id = await register(client)
        other = await register(client)
        for overrides in [
            {"resource": "https://other.invalid/mcp"},
            {"redirect_uri": "https://evil.invalid/callback"},
            {"code_challenge_method": "plain"},
        ]:
            response = await client.get(
                "/authorize",
                params={
                    "client_id": client_id,
                    "redirect_uri": CALLBACK,
                    "response_type": "code",
                    "code_challenge": CHALLENGE,
                    "scope": "mijia",
                    **overrides,
                },
            )
            assert response.status_code in {302, 400}
            assert "/oauth/consent" not in response.headers.get("location", "")
        data = await grant(client, client_id)
        assert (await client.post("/token", data={**data, "client_id": other})).status_code == 401
        assert (
            await client.post("/token", data={**data, "redirect_uri": "https://evil.invalid/"})
        ).status_code == 400
        token = (await client.post("/token", data=data)).json()
        provider = OwnerOAuthProvider(BASE, tmp_path, TEST_KEYS)
        with provider.db() as db:
            db.execute(
                "UPDATE entries SET expires=? WHERE kind='access' AND id=?",
                (time.time() - 1, digest(token["access_token"])),
            )
        assert (
            await rpc(client, "tools/list", authorization="Bearer " + token["access_token"])
        ).status_code == 401
        data = await grant(client, client_id)
        token = (await client.post("/token", data=data)).json()
    async with http_client(Settings((SECOND_KEY,), tmp_path, public_url=BASE)) as client:
        assert (
            await rpc(client, "tools/list", authorization="Bearer " + token["access_token"])
        ).status_code == 401
        refresh = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": token["refresh_token"],
        }
        assert (await client.post("/token", data=refresh)).status_code == 401


async def test_consent_cookie_origin_denial_and_unregistered_redirects(tmp_path):
    async with http_client(Settings(TEST_KEYS, tmp_path, public_url=BASE)) as client:
        client_id = await register(client)
        fields = await consent_page(client, client_id)
        data = {**fields, "api_key": TEST_KEY, "decision": "allow"}
        assert (
            await client.post(
                "/oauth/consent", data=data, headers={"Origin": "https://evil.invalid"}
            )
        ).status_code == 403
        assert (
            await client.post("/oauth/consent", data=data, headers={"Origin": "null"})
        ).status_code == 403
        client.cookies.clear()
        assert (await client.post("/oauth/consent", data=data)).status_code == 403
        fields = await consent_page(client, client_id)
        denial = await client.post("/oauth/consent", data={**fields, "decision": "deny"})
        assert parse_qs(urlparse(denial.headers["location"]).query)["error"] == ["access_denied"]
        assert (
            await client.post("/oauth/consent", data={**fields, "api_key": TEST_KEY})
        ).status_code == 403
        insecure = await client.post(
            "/register",
            json={
                "redirect_uris": ["http://public.invalid/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert insecure.status_code == 400


@pytest.mark.parametrize("decision", ["allow", "deny"])
async def test_browser_consent_preserves_origin_and_allows_only_client_callback(tmp_path, decision):
    callback = "https://chatgpt.com/connector/oauth/test?existing=value"
    async with http_client(Settings(TEST_KEYS, tmp_path, public_url=BASE)) as client:
        client_id = await register(client, callback)
        fields = await consent_page(client, client_id, redirect_uri=callback)
        response = await client.post(
            "/oauth/consent",
            data={**fields, "api_key": TEST_KEY, "decision": decision},
            headers={"Origin": BASE},
        )
        assert response.status_code == 302
        assert response.headers["referrer-policy"] == "same-origin"
        assert response.headers["content-security-policy"] == (
            "default-src 'none'; form-action 'self' https://chatgpt.com; frame-ancestors 'none'"
        )
        location = urlparse(response.headers["location"])
        assert location.netloc == "chatgpt.com"
        query = parse_qs(location.query)
        assert query["existing"] == ["value"]
        assert query["state"] == ["test-state"]
        assert ("code" in query) == (decision == "allow")
        assert ("error" in query) == (decision == "deny")
        assert TEST_KEY not in response.headers["location"]


@pytest.mark.parametrize(
    "callback", ["https://*.example.com/callback", "https://bad;host/callback"]
)
async def test_registration_rejects_csp_source_metacharacters(tmp_path, callback):
    async with http_client(Settings(TEST_KEYS, tmp_path, public_url=BASE)) as client:
        response = await client.post(
            "/register",
            json={
                "redirect_uris": [callback],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert response.status_code == 400


def test_railway_domain_enables_oauth_without_extra_credentials():
    settings = Settings.from_env(
        {
            "ALLOWED_API_KEYS": '["' + TEST_KEY + '"]',
            "RAILWAY_PUBLIC_DOMAIN": "mijiamcp-production.up.railway.app",
        }
    )
    assert settings.public_url == "https://mijiamcp-production.up.railway.app"
