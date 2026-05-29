"""Главный handler для всех маршрутов /labs/*."""
from __future__ import annotations

import hmac as _hmac
import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

_IMPORT_ERROR = None
LAB_MODULES = {}
LABS = {}
flag_for = None  # type: ignore

try:
    from _labs.common import LABS  # noqa: F811
    from _labs.common import flag_for  # noqa: F811
    from _labs import sqli as _sqli
    from _labs import xss as _xss
    from _labs import idor as _idor
    from _labs import cmdi as _cmdi
    from _labs import path_traversal as _pt
    LAB_MODULES = {
        "sqli": _sqli,
        "xss": _xss,
        "idor": _idor,
        "cmdi": _cmdi,
        "path_traversal": _pt,
    }
except Exception as _e:
    _IMPORT_ERROR = (
        f"{type(_e).__name__}: {_e}\n\n"
        f"--- traceback ---\n{traceback.format_exc()}"
    )


def _json_resp(status, payload):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return status, [("Content-Type", "application/json; charset=utf-8")], body


def _extract_vp(self_path):
    parsed = urlparse(self_path)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    vp = qs.pop("vp", [""])[0]
    if not vp:
        p = parsed.path or ""
        if p.startswith("/labs/"):
            vp = p[len("/labs/"):]
        elif p in ("/labs", "/labs/"):
            vp = ""
    return vp, qs, parsed.path


def _do_dispatch(method, vp, qs, headers, body, raw_path):
    if _IMPORT_ERROR:
        return _json_resp(500, {"error": "import_error", "detail": _IMPORT_ERROR})

    vp = (vp or "").strip("/")

    # /labs/  -> список лаб
    if vp == "":
        return _json_resp(200, {
            "labs": [
                LABS[s].to_dict()
                for s in sorted(LABS, key=lambda s: LABS[s].order)
            ]
        })

    parts = vp.split("/", 1)
    slug = parts[0]
    sub = parts[1] if len(parts) > 1 else ""

    if slug not in LAB_MODULES:
        return _json_resp(404, {"error": f"unknown lab: {slug}"})

    module = LAB_MODULES[slug]

    # /labs/<slug>/template -> JSON {spec, template, variant}
    if sub == "template" and method == "GET":
        u_val = qs.get("u")
        if isinstance(u_val, list):
            u_val = u_val[0] if u_val else ""
        u_val = u_val or ""
        variant_info = None
        template_src = getattr(module, "TEMPLATE_SOURCE", "")
        if hasattr(module, "VARIANT_NAMES") and hasattr(module, "variant_meta"):
            from _labs.common import variant_for as _vf  # noqa: F811
            vname = _vf(slug, u_val, module.VARIANT_NAMES)
            variant_info = module.variant_meta(vname)
            if hasattr(module, "get_template"):
                template_src = module.get_template(u_val)
        return _json_resp(200, {
            "spec": LABS[slug].to_dict(),
            "template": template_src,
            "variant": variant_info,
        })

    # /labs/<slug>/check -> POST {"code": "..."}, u в query
    if sub == "check":
        if method == "GET":
            return _json_resp(200, {
                "info": "POST application/json {\"code\": \"...\"}",
            })
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return _json_resp(400, {"error": f"invalid JSON body: {e}"})
        code = payload.get("code", "")
        if not isinstance(code, str):
            return _json_resp(400, {"error": "field 'code' must be a string"})
        u_val = qs.get("u")
        if isinstance(u_val, list):
            u_val = u_val[0] if u_val else ""
        u_val = u_val or ""
        # Поддержка обоих сигнатур: check(code) и check(code, u)
        import inspect
        try:
            sig = inspect.signature(module.check)
            if len(sig.parameters) >= 2:
                result = module.check(code, u_val)
            else:
                result = module.check(code)
        except (TypeError, ValueError):
            result = module.check(code)
        return _json_resp(200, result)

    # /labs/<slug>/verify-flag -> POST {"flag": "..."}
    if sub == "verify-flag" and method == "POST":
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return _json_resp(400, {"error": f"invalid JSON body: {e}"})
        submitted = (payload.get("flag") or "").strip()
        u = (qs.get("u") or [""])[0] if isinstance(qs.get("u"), list) else (qs.get("u") or "")
        expected = flag_for(slug, u)
        ok = _hmac.compare_digest(submitted, expected)
        return _json_resp(200, {"ok": ok})

    # Иначе — отдаём управление модулю лабы
    resp = module.handle(method, sub, headers, body, qs)
    body_out = resp.body
    if isinstance(body_out, str):
        body_out = body_out.encode("utf-8")
    return resp.status, resp.headers, body_out


class handler(BaseHTTPRequestHandler):
    def do_GET(self):  self._serve("GET")
    def do_POST(self): self._serve("POST")
    def do_PUT(self):  self._serve("PUT")
    def do_DELETE(self): self._serve("DELETE")

    def _serve(self, method):
        try:
            vp, qs, raw_path = _extract_vp(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            headers_dict = {k.lower(): v for k, v in self.headers.items()}
            qs_flat = {k: v for k, v in qs.items()}

            status, hdrs, body_out = _do_dispatch(
                method, vp, qs_flat, headers_dict, body, raw_path
            )
            self.send_response(status)
            for name, value in hdrs:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body_out)
        except Exception as e:
            err_body = json.dumps({
                "error": type(e).__name__,
                "message": str(e),
            }, ensure_ascii=False).encode("utf-8")
            try:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(err_body)
            except Exception:
                pass
