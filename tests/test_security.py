import importlib
import subprocess
import sys
import time

import jwt
import pytest
from fastapi.testclient import TestClient

import main
import routes.auth as auth
import routes.chargers as chargers
import shared

ROOT = __file__.rsplit("/tests/", 1)[0]


def _token():
    return jwt.encode({"sub": "1", "email": "a@b.c", "exp": int(time.time()) + 600},
                      "test-secret", algorithm="HS256")


@pytest.fixture()
def client(monkeypatch):
    async def ok_status(strict=False):
        return {"complete": True}
    monkeypatch.setattr(main, "get_setup_status", ok_status)
    auth._failures.clear()
    return TestClient(main.app, follow_redirects=False)


def test_empty_secret_refuses_to_start():
    env = {"PATH": "/usr/bin:/bin", "JWT_SECRET": "", "CORE_API_KEY": ""}
    r = subprocess.run([sys.executable, "-c", "import shared"], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "Refusing to start" in r.stderr


@pytest.mark.parametrize("path,public", [
    ("/login", True), ("/setup", True), ("/setup/start", True), ("/health", True),
    ("/static/logo.svg", True), ("/setupXYZ", False), ("/healthXYZ", False),
    ("/loginx", False), ("/chargers", False),
])
def test_public_path_boundary(path, public):
    assert main._is_public(path) is public


def test_non_public_paths_require_auth(client):
    for p in ("/setupXYZ", "/healthXYZ"):
        r = client.get(p)
        assert r.status_code == 302 and r.headers["location"] == "/login"


def test_setup_check_fails_closed(monkeypatch):
    async def boom(strict=False):
        raise RuntimeError("down")
    monkeypatch.setattr(main, "get_setup_status", boom)
    c = TestClient(main.app, follow_redirects=False)
    assert c.get("/chargers").status_code == 503
    assert c.get("/login").status_code == 200


def test_csrf_cross_origin_rejected(client):
    client.cookies.set("opencpo_session", _token())
    r = client.post("/logout", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    r = client.post("/logout", headers={"Origin": "http://testserver"})
    assert r.status_code == 302


def test_logout_get_not_allowed(client):
    assert client.get("/logout").status_code == 405


def test_login_rate_limit(client, monkeypatch):
    class R:
        status_code = 401
        def json(self):
            return {"detail": "Invalid email or password."}

    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return R()

    monkeypatch.setattr(auth.httpx, "AsyncClient", C)
    codes = [client.post("/login", data={"email": "a@b.c", "password": "x"}).status_code
             for _ in range(11)]
    assert codes[:10] == [200] * 10
    assert codes[10] == 429


def test_security_headers(client):
    r = client.get("/login")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "content-security-policy" in r.headers


def test_error_text_is_escaped(client, monkeypatch):
    payload = "<script>alert(1)</script>"

    async def failing_api(*a, **k):
        raise RuntimeError(payload)

    monkeypatch.setattr(chargers, "api", failing_api)
    client.cookies.set("opencpo_session", _token())
    r = client.post("/action/charger/delete/CP1", headers={"Origin": "http://testserver"})
    assert payload not in r.text
    assert "&lt;script&gt;" in r.text
