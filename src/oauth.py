"""Persistent OAuth authorization-code provider, gated by the owner's existing API key."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse

from fastmcp.server.auth import AccessToken, OAuthProvider
from fastmcp.server.auth.auth import TokenHandler
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.routes import cors_middleware
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

SCOPE = "mijia"
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    # Chromium sends Origin: null for form POSTs under no-referrer, which
    # correctly fails our origin check. Preserve same-origin form provenance
    # while still suppressing Referer on the cross-origin OAuth callback.
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def consent_headers(redirect_uri: str) -> dict[str, str]:
    """Allow only this validated client's callback in the form redirect chain."""
    callback = urlparse(redirect_uri)
    # Chromium applies form-action to redirects as well as the form's POST.
    # Keep the form itself same-origin and allow its registered callback origin.
    callback_origin = f"{callback.scheme}://{callback.netloc}"
    return {
        **SECURITY_HEADERS,
        "Content-Security-Policy": (
            f"default-src 'none'; form-action 'self' {callback_origin}; frame-ancestors 'none'"
        ),
    }


class OwnerOAuthProvider(OAuthProvider):
    """Use SDK protocol handlers; retain only hashed bearer secrets in SQLite."""

    def __init__(self, base_url: str, data_dir: Path, allowed_api_keys: tuple[str, ...]):
        parsed = urlparse(base_url)
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not parsed.hostname
            or not (
                parsed.scheme == "https"
                or (
                    parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                )
            )
        ):
            raise ValueError("MIJIA_PUBLIC_URL must be an HTTPS origin or a local HTTP origin")
        super().__init__(
            base_url=base_url,
            required_scopes=[SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.origin = base_url.rstrip("/")
        self.key_digests = tuple(digest(key) for key in allowed_api_keys)
        self.db_path = data_dir / "oauth.sqlite3"
        with self.db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS entries "
                "(kind TEXT, id TEXT, body TEXT, expires REAL, PRIMARY KEY(kind,id))"
            )
        self.db_path.chmod(0o600)

    def db(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def save(self, db, kind, identifier, body, lifetime):
        db.execute("DELETE FROM entries WHERE expires <= ?", (time.time(),))
        db.execute(
            "INSERT OR REPLACE INTO entries VALUES (?,?,?,?)",
            (kind, digest(identifier), json.dumps(body), time.time() + lifetime),
        )

    def read(self, db, kind, identifier, consume=False):
        statement = (
            "DELETE FROM entries WHERE kind=? AND id=? AND expires>? RETURNING body"
            if consume
            else "SELECT body FROM entries WHERE kind=? AND id=? AND expires>?"
        )
        row = db.execute(statement, (kind, digest(identifier), time.time())).fetchone()
        return json.loads(row[0]) if row else None

    def owner_valid(self, owner_digest):
        return any(hmac.compare_digest(owner_digest, key) for key in self.key_digests)

    async def get_client(self, client_id):
        with self.db() as db:
            record = self.read(db, "client", client_id)
        return OAuthClientInformationFull.model_validate(record) if record else None

    async def register_client(self, client_info):
        for uri in client_info.redirect_uris or []:
            parsed = urlparse(str(uri))
            if (
                parsed.username
                or parsed.password
                or parsed.fragment
                or not parsed.hostname
                or not re.fullmatch(r"[A-Za-z0-9.:-]+", parsed.hostname)
                or not (
                    parsed.scheme == "https"
                    or (
                        parsed.scheme == "http"
                        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                    )
                )
            ):
                raise RegistrationError("invalid_redirect_uri", "Use HTTPS or a loopback callback.")
        if client_info.token_endpoint_auth_method not in {
            "none",
            "client_secret_post",
            "client_secret_basic",
        }:
            raise RegistrationError("invalid_client_metadata", "Unsupported client authentication.")
        with self.db() as db:
            self.save(
                db,
                "client",
                client_info.client_id,
                client_info.model_dump(mode="json"),
                365 * 86400,
            )

    async def authorize(self, client, params):
        if params.resource not in {None, str(self._resource_url)}:
            raise AuthorizeError("invalid_request", "Invalid resource indicator.")
        if not params.scopes or set(params.scopes) != {SCOPE}:
            raise AuthorizeError("invalid_scope", "The mijia scope is required.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge):
            raise AuthorizeError("invalid_request", "A SHA-256 PKCE challenge is required.")
        request_id = secrets.token_urlsafe(32)
        with self.db() as db:
            self.save(
                db,
                "request",
                request_id,
                {
                    "client_id": client.client_id,
                    "params": params.model_dump(mode="json"),
                },
                600,
            )
        return f"{self.origin}/oauth/consent?{urlencode({'request': request_id})}"

    def error_page(self, status=400):
        return HTMLResponse(
            "授权请求无效或已过期，请返回客户端重新连接。",
            status_code=status,
            headers=SECURITY_HEADERS,
        )

    async def consent(self, request: Request) -> Response:
        if request.method == "GET":
            request_id = request.query_params.get("request", "")
            with self.db() as db:
                record = self.read(db, "request", request_id)
                if not record:
                    return self.error_page()
                csrf = secrets.token_urlsafe(32)
                record["csrf"] = digest(csrf)
                self.save(db, "request", request_id, record, 600)
            client = await self.get_client(record["client_id"])
            if not client:
                return self.error_page()
            redirect = html.escape(record["params"]["redirect_uri"])
            name = html.escape(client.client_name or "OAuth 客户端")
            response = HTMLResponse(
                f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>米家家居授权</title>
<body><h1>米家家居授权</h1><p>应用：{name}（应用名称由客户端提供）</p>
<p>回调地址：<code>{redirect}</code></p>
<p>允许该应用查询和控制你的米家设备、执行场景及发起米家扫码登录。
仅向你信任的客户端授权。请输入现有米家 MCP API Key 确认，Key 只发送到本服务。</p>
<form method="post" action="/oauth/consent">
<input type="hidden" name="request" value="{html.escape(request_id)}">
<input type="hidden" name="csrf" value="{csrf}">
<label>API Key <input type="password" name="api_key" required
autocomplete="off" maxlength="4096"></label>
<button name="decision" value="allow">授权连接</button>
<button name="decision" value="deny" formnovalidate>拒绝</button></form></body></html>''',
                headers=consent_headers(record["params"]["redirect_uri"]),
            )
            response.set_cookie(
                f"mijia_{request_id}",
                csrf,
                max_age=600,
                path="/oauth/consent",
                secure=self.origin.startswith("https://"),
                httponly=True,
                samesite="strict",
            )
            return response

        if request.headers.get("origin") not in {None, self.origin}:
            return self.error_page(403)
        if int(request.headers.get("content-length", "0")) > 16384:
            return self.error_page(413)
        form = await request.form(max_fields=8, max_files=0)
        request_id = str(form.get("request", ""))
        csrf = str(form.get("csrf", ""))
        cookie = request.cookies.get(f"mijia_{request_id}", "")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            record = self.read(db, "request", request_id)
            if (
                not record
                or not csrf
                or not cookie
                or not hmac.compare_digest(digest(csrf), digest(cookie))
                or not hmac.compare_digest(record.get("csrf", ""), digest(csrf))
            ):
                return self.error_page(403)
            params = AuthorizationParams.model_validate(record["params"])
            if form.get("decision") == "deny":
                self.read(db, "request", request_id, consume=True)
                redirect = construct_redirect_uri(
                    str(params.redirect_uri), error="access_denied", state=params.state
                )
            else:
                owner_digest = digest(str(form.get("api_key", "")))
                if not self.owner_valid(owner_digest):
                    return HTMLResponse(
                        "API Key 无效。请返回客户端重新连接。",
                        status_code=401,
                        headers=SECURITY_HEADERS,
                    )
                self.read(db, "request", request_id, consume=True)
                code = secrets.token_urlsafe(32)
                value = AuthorizationCode(
                    code="",
                    client_id=record["client_id"],
                    expires_at=time.time() + 120,
                    subject="myhome-owner",
                    **params.model_dump(exclude={"state"}),
                ).model_dump(mode="json", exclude={"code"})
                value["owner_digest"] = owner_digest
                value["resource"] = str(self._resource_url)
                self.save(db, "code", code, value, 120)
                redirect = construct_redirect_uri(
                    str(params.redirect_uri), code=code, state=params.state
                )
        response = RedirectResponse(
            redirect, status_code=302, headers=consent_headers(str(params.redirect_uri))
        )
        response.delete_cookie(f"mijia_{request_id}", path="/oauth/consent")
        return response

    async def load_authorization_code(self, client, authorization_code):
        with self.db() as db:
            record = self.read(db, "code", authorization_code)
        if not record or record["client_id"] != client.client_id:
            return None
        return AuthorizationCode(code=authorization_code, **record)

    def mint(self, db, client, record, scopes):
        if not self.owner_valid(record["owner_digest"]):
            raise TokenError("invalid_grant", "Owner credential is no longer valid.")
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        family = record.get("family", secrets.token_urlsafe(32))
        value = {
            "client_id": client.client_id,
            "scopes": scopes,
            "resource": str(self._resource_url),
            "subject": "myhome-owner",
            "owner_digest": record["owner_digest"],
            "family": family,
        }
        self.save(db, "access", access, {**value, "expires_at": int(time.time()) + 3600}, 3600)
        self.save(
            db,
            "refresh",
            refresh,
            {**value, "expires_at": int(time.time()) + 30 * 86400},
            30 * 86400,
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=3600,
            refresh_token=refresh,
            scope=" ".join(scopes),
        )

    async def exchange_authorization_code(self, client, authorization_code):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            record = self.read(db, "code", authorization_code.code, consume=True)
            if not record or record["client_id"] != client.client_id:
                raise TokenError("invalid_grant", "Authorization code is expired or already used.")
            return self.mint(db, client, record, record["scopes"])

    async def load_refresh_token(self, client, refresh_token):
        with self.db() as db:
            record = self.read(db, "refresh", refresh_token)
            used = self.read(db, "used_refresh", refresh_token)
            if used and used["client_id"] == client.client_id:
                self.revoke_family(db, used["family"])
        if not record or record["client_id"] != client.client_id:
            return None
        return RefreshToken(token=refresh_token, **record)

    def revoke_family(self, db, family):
        db.execute(
            "DELETE FROM entries WHERE kind IN ('access','refresh') "
            "AND json_extract(body,'$.family')=?",
            (family,),
        )

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            record = self.read(db, "refresh", refresh_token.token, consume=True)
            if not record or record["client_id"] != client.client_id:
                raise TokenError("invalid_grant", "Refresh token is expired or already used.")
            self.revoke_family(db, record["family"])
            self.save(db, "used_refresh", refresh_token.token, record, 30 * 86400)
            return self.mint(db, client, record, scopes)

    async def load_access_token(self, token):
        with self.db() as db:
            record = self.read(db, "access", token)
        if (
            not record
            or not self.owner_valid(record["owner_digest"])
            or record["resource"] != str(self._resource_url)
        ):
            return None
        return AccessToken(token=token, **record)

    async def revoke_token(self, token):
        with self.db() as db:
            record = self.read(
                db, "refresh" if isinstance(token, RefreshToken) else "access", token.token
            )
            if record:
                self.revoke_family(db, record["family"])

    def get_routes(self, mcp_path=None):
        routes = super().get_routes(mcp_path)
        for route in routes:
            if route.path == "/token":
                endpoint = TokenHandler(
                    provider=self, client_authenticator=ClientAuthenticator(self)
                ).handle

                async def resource_bound_token(request):
                    if request.method == "POST":
                        form = await request.form()
                        if form.get("resource") not in {None, str(self._resource_url)}:
                            return JSONResponse(
                                {"error": "invalid_target"},
                                status_code=400,
                                headers={"Cache-Control": "no-store"},
                            )
                    return await endpoint(request)

                routes[routes.index(route)] = Route(
                    "/token",
                    cors_middleware(resource_bound_token, ["POST", "OPTIONS"]),
                    methods=["POST", "OPTIONS"],
                )
                break
        return [*routes, Route("/oauth/consent", self.consent, methods=["GET", "POST"])]
