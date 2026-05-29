"""Общие утилиты для всех лаб."""
from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote


# =========================================================================
# Реестр лаб
# =========================================================================

@dataclass(frozen=True)
class LabSpec:
    slug: str
    title: str
    vulnerability: str
    description: str
    instructions: str
    flag_template: str   # типа "FLAG{{sqli_auth_bypass_{token}}}"
    order: int

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "title": self.title,
            "vulnerability": self.vulnerability,
            "description": self.description,
            "instructions": self.instructions,
            "order": self.order,
            "run_path": f"/labs/{self.slug}/run/",
            "check_path": f"/labs/{self.slug}/check",
            "verify_flag_path": f"/labs/{self.slug}/verify-flag",
        }


LABS: dict[str, LabSpec] = {
    "sqli": LabSpec(
        slug="sqli",
        title="SQL Injection: обход аутентификации",
        vulnerability="SQL Injection (CWE-89)",
        description=(
            "Уязвимое приложение — простая форма входа. SQL-запрос строится "
            "конкатенацией с пользовательским вводом. Ваша задача — войти "
            "как пользователь admin, не зная его пароля."
        ),
        instructions=(
            "1. Откройте уязвимое приложение.\n"
            "2. Подберите SQL-инъекцию для поля username.\n"
            "3. После успешного входа на странице будет показан флаг — "
            "вставьте его в форму ниже."
        ),
        flag_template="FLAG{{sqli_auth_bypass_{token}}}",
        order=1,
    ),
    "xss": LabSpec(
        slug="xss",
        title="Stored XSS: внедрение скрипта в комментарий",
        vulnerability="Stored Cross-Site Scripting (CWE-79)",
        description=(
            "Блог с комментариями. Текст сохраняется и отображается без "
            "экранирования HTML. Ваша задача — оставить комментарий, "
            "который выполнит JavaScript у любого посетителя."
        ),
        instructions=(
            "1. Откройте уязвимое приложение.\n"
            "2. Оставьте комментарий с тегом <script> или onerror у <img>.\n"
            "3. Если код выполнится — на странице появится флаг."
        ),
        flag_template="FLAG{{stored_xss_script_executed_{token}}}",
        order=2,
    ),
    "idor": LabSpec(
        slug="idor",
        title="IDOR: чтение чужих заметок",
        vulnerability="Insecure Direct Object Reference (CWE-639)",
        description=(
            "Сервис заметок. Маршрут /note/<id> не проверяет владельца. "
            "Вы залогинены как alice — прочитайте секретную заметку bob."
        ),
        instructions=(
            "1. Откройте уязвимое приложение — вы alice.\n"
            "2. Перебирая числовые id в адресной строке, найдите заметку "
            "bob с флагом."
        ),
        flag_template="FLAG{{idor_read_other_users_data_{token}}}",
        order=3,
    ),
    "cmdi": LabSpec(
        slug="cmdi",
        title="Command Injection: подмена аргументов",
        vulnerability="OS Command Injection (CWE-78)",
        description=(
            "Утилита ping. Введённый адрес подставляется в shell-команду "
            "через конкатенацию, позволяя внедрить произвольную команду. "
            "Прочитайте /etc/lab_flag."
        ),
        instructions=(
            "1. Откройте уязвимое приложение.\n"
            "2. Используя ; | && внедрите команду чтения /etc/lab_flag.\n"
            "3. Вывод появится на странице."
        ),
        flag_template="FLAG{{command_injection_rce_{token}}}",
        order=4,
    ),
    "path_traversal": LabSpec(
        slug="path_traversal",
        title="Path Traversal: чтение файла вне директории",
        vulnerability="Path Traversal (CWE-22)",
        description=(
            "Просмотрщик файлов. Имя файла подставляется в путь без "
            "нормализации. Выйдите из публичной директории и прочитайте "
            "файл с флагом."
        ),
        instructions=(
            "1. Откройте уязвимое приложение.\n"
            "2. Через ?file=... и последовательности ../ прочитайте "
            "secret/flag.txt."
        ),
        flag_template="FLAG{{path_traversal_escape_{token}}}",
        order=5,
    ),
}


# =========================================================================
# Per-user флаги
# =========================================================================

_FLAG_SECRET = os.environ.get(
    "LAB_FLAG_SECRET",
    "dev-flag-secret-do-not-use-in-prod-b2d4f6a8c0",
).encode()


def flag_for(slug: str, user: str = "") -> str:
    """Детерминированный флаг для конкретного user (LTI sub@iss).

    Без user возвращает флаг с фиксированным токеном (для прямого
    захода или demo). С user — уникальный токен на пользователя.
    """
    spec = LABS[slug]
    h = hmac.new(
        _FLAG_SECRET, f"{slug}:{user}".encode("utf-8"), hashlib.sha256
    ).digest()
    token = h.hex()[:6]
    return spec.flag_template.format(token=token)


def variant_for(slug: str, user: str, variants: list[str]) -> str:
    """Детерминированно выбирает вариант стенда для пользователя.
    Один и тот же пользователь всегда получает один и тот же вариант;
    разные пользователи — разные.
    """
    if not variants:
        return ""
    h = hashlib.sha256(
        f"variant:{slug}:{user}".encode("utf-8")
    ).digest()
    idx = int.from_bytes(h[:4], "big") % len(variants)
    return variants[idx]


# =========================================================================
# Response object
# =========================================================================

@dataclass
class Resp:
    status: int = 200
    headers: list = field(default_factory=list)
    body: bytes | str = b""

    @classmethod
    def html(cls, body: str, status: int = 200) -> "Resp":
        return cls(
            status=status,
            headers=[("Content-Type", "text/html; charset=utf-8")],
            body=body.encode("utf-8"),
        )

    @classmethod
    def json(cls, payload: Any, status: int = 200) -> "Resp":
        return cls(
            status=status,
            headers=[("Content-Type", "application/json; charset=utf-8")],
            body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        )

    @classmethod
    def redirect(cls, location: str, status: int = 302) -> "Resp":
        return cls(status=status, headers=[("Location", location)], body=b"")

    @classmethod
    def text(cls, body: str, status: int = 200) -> "Resp":
        return cls(
            status=status,
            headers=[("Content-Type", "text/plain; charset=utf-8")],
            body=body.encode("utf-8"),
        )

    @classmethod
    def not_found(cls) -> "Resp":
        return cls.html("<h1>404 Not Found</h1>", status=404)


# =========================================================================
# HTML helpers
# =========================================================================

def esc(s: Any) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def u_qs(u: str) -> str:
    """Хвост ?u=<user>, безопасный для подстановки в URL. Пустой если u пуст."""
    return f"?u={quote(u, safe='')}" if u else ""


def page(title: str, content: str, theme: str = "dark") -> str:
    if theme == "dark":
        bg = "linear-gradient(135deg, #1e293b 0%, #0f172a 100%)"
        fg = "#e2e8f0"
        card_bg = "rgba(15, 23, 42, 0.9)"
        card_border = "#334155"
    else:
        bg = "#fafaf9"
        fg = "#1c1917"
        card_bg = "white"
        card_border = "#e7e5e4"

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;
       background:{bg};color:{fg};margin:0;min-height:100vh;
       display:flex;align-items:center;justify-content:center;padding:2rem}}
  .lab-card{{background:{card_bg};border:1px solid {card_border};
       border-radius:16px;padding:2.5rem;max-width:560px;width:100%;
       box-shadow:0 20px 60px rgba(0,0,0,0.4)}}
  h1{{margin:0 0 .5rem;font-size:1.5rem}}
  .subtitle{{color:#94a3b8;font-size:.875rem;margin-bottom:1.5rem}}
  label{{display:block;font-size:.85rem;color:#cbd5e1;margin:.75rem 0 .25rem}}
  input[type=text],input[type=password],textarea{{
       width:100%;padding:.7rem .9rem;background:#0f172a;
       border:1px solid #334155;color:#e2e8f0;border-radius:8px;
       font-size:.95rem;font-family:ui-monospace,monospace}}
  input:focus,textarea:focus{{outline:none;border-color:#3b82f6}}
  button{{padding:.7rem 1.2rem;background:#3b82f6;color:white;border:0;
       border-radius:8px;font-weight:600;font-size:.95rem;cursor:pointer}}
  button:hover{{background:#2563eb}}
  button.primary-full{{width:100%;margin-top:1.25rem;padding:.8rem}}
  .error{{background:rgba(239,68,68,0.15);border:1px solid #ef4444;
       color:#fca5a5;padding:.75rem;border-radius:8px;
       font-size:.85rem;margin-bottom:1rem;word-break:break-all}}
  code{{background:#1e293b;padding:.1rem .4rem;border-radius:4px;
       font-family:ui-monospace,monospace}}
  .flag{{background:#064e3b;border:2px dashed #10b981;color:#6ee7b7;
       padding:1rem;margin:1rem 0;font-family:ui-monospace,monospace;
       font-size:1.05rem;border-radius:8px;word-break:break-all}}
  .badge{{display:inline-block;padding:.2rem .6rem;border-radius:999px;
       background:#ef4444;color:white;font-size:.7rem;font-weight:700;
       letter-spacing:.05em;text-transform:uppercase;margin-bottom:.6rem}}
  a{{color:#93c5fd}}
  pre{{background:#020617;border:1px solid #1e293b;border-radius:8px;
       padding:1rem;font-family:ui-monospace,monospace;font-size:.85rem;
       color:#86efac;max-height:360px;overflow:auto;line-height:1.5;
       margin:.6rem 0;white-space:pre-wrap;word-break:break-all}}
  .hint{{margin-top:1rem;padding:.6rem .9rem;background:rgba(59,130,246,.1);
       border:1px solid rgba(59,130,246,.3);border-radius:8px;
       font-size:.85rem;color:#93c5fd}}
</style></head><body>
<div class="lab-card">{content}</div>
</body></html>"""


# =========================================================================
# Парсинг
# =========================================================================

def parse_form(body: bytes | str) -> dict[str, str]:
    from urllib.parse import parse_qs
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            body = body.decode("utf-8", errors="replace")
    parsed = parse_qs(body, keep_blank_values=True)
    return {k: v[0] if v else "" for k, v in parsed.items()}


def parse_cookies(header: str | None) -> dict[str, str]:
    if not header:
        return {}
    out: dict[str, str] = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out


def get_u(qs: dict) -> str:
    """Извлекает user identifier из query string."""
    val = qs.get("u")
    if isinstance(val, list):
        return val[0] if val else ""
    if isinstance(val, str):
        return val
    return ""


# =========================================================================
# Подписанные cookies для stateful лаб (XSS)
# =========================================================================

_SECRET = os.environ.get(
    "LAB_STATE_SECRET",
    "dev-secret-do-not-use-in-prod-19a8f2c0e4b3d56e",
).encode()


def sign_state(payload: dict) -> str:
    body = base64.urlsafe_b64encode(
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ).decode("ascii").rstrip("=")
    sig = hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{body}.{sig}"


def verify_state(value: str | None) -> dict | None:
    if not value or "." not in value:
        return None
    body, sig = value.rsplit(".", 1)
    expected = hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = body + "=" * (-len(body) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


# =========================================================================
# AST-хелперы
# =========================================================================

def parse_safe(code: str) -> ast.AST | None:
    try:
        return ast.parse(code)
    except SyntaxError:
        return None


def find_function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    return None


def has_fstring(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr):
            return True
    return False


def has_format_call(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr == "format":
                return True
    return False


def has_percent_format(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
            if isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
                return True
    return False


def has_string_concat_with_name(node: ast.AST, names: set[str]) -> bool:
    def name_of(n):
        return isinstance(n, ast.Name) and n.id in names

    for n in ast.walk(node):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            if name_of(n.left) or name_of(n.right):
                return True
            if isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
                if name_of(n.right):
                    return True
            if isinstance(n.right, ast.Constant) and isinstance(n.right.value, str):
                if name_of(n.left):
                    return True
    return False


def calls_method_min_args(node: ast.AST, method: str, min_args: int) -> bool:
    for n in ast.walk(node):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == method
                and len(n.args) >= min_args):
            return True
    return False


def calls_any_attr(node: ast.AST, attrs: set[str]) -> bool:
    for n in ast.walk(node):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in attrs):
            return True
    return False


def compares_attribute(node: ast.AST, attr: str) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Compare):
            for operand in [n.left, *n.comparators]:
                if isinstance(operand, ast.Attribute) and operand.attr == attr:
                    return True
                if (isinstance(operand, ast.Call)
                        and isinstance(operand.func, ast.Attribute)
                        and operand.func.attr == "get"
                        and operand.args
                        and isinstance(operand.args[0], ast.Constant)
                        and operand.args[0].value == attr):
                    return True
                if (isinstance(operand, ast.Subscript)
                        and isinstance(operand.slice, ast.Constant)
                        and operand.slice.value == attr):
                    return True
    return False


def passes_list_to_call(node: ast.AST, func_attr: str) -> bool:
    for n in ast.walk(node):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == func_attr
                and n.args
                and isinstance(n.args[0], (ast.List, ast.Tuple))):
            return True
    return False


def contains_constant_string(node: ast.AST, needle: str) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if needle in n.value:
                return True
    return False


def imports_module(tree: ast.AST, name: str) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name == name:
                    return True
        if isinstance(n, ast.ImportFrom) and n.module == name:
            return True
    return False
