"""Лаба SQLi: два варианта с разными задачами и решениями."""
from __future__ import annotations

import ast
import sqlite3

from .common import (
    LABS, Resp, esc, page, parse_form, get_u, u_qs, flag_for, variant_for,
    parse_safe, find_function, has_fstring, has_format_call,
    has_percent_format, has_string_concat_with_name,
    calls_method_min_args,
)


# =========================================================================
# Реестр вариантов
# =========================================================================

VARIANTS: dict[str, dict] = {
    "bank_login": {
        "label": "Обход аутентификации (SecureBank)",
        "service": "SecureBank",
    },
    "user_lookup": {
        "label": "Поиск пользователя по ID (UserDB)",
        "service": "UserDB",
    },
}
VARIANT_NAMES = list(VARIANTS.keys())


def variant_meta(name: str) -> dict:
    cfg = VARIANTS.get(name) or VARIANTS[VARIANT_NAMES[0]]
    return {"name": name or VARIANT_NAMES[0], "label": cfg["label"]}


# =========================================================================
# Вариант A: bank_login — обход аутентификации через WHERE
# =========================================================================

_TEMPLATE_BANK_LOGIN = '''"""
Уязвимая аутентификация. Закройте SQL-инъекцию.
Менять можно ТОЛЬКО строки между маркерами EDIT-START / EDIT-END.

    conn  — sqlite3.Connection
    username, password — строки от пользователя

Должна вернуть:
    {"id": int, "username": str, "is_admin": bool} — при успехе
    None — при неверных credentials
"""
import sqlite3


def login(conn, username, password):
    cur = conn.cursor()
    # EDIT-START: query
    sql = (
        "SELECT id, username, is_admin FROM users "
        f"WHERE username=\\'{username}\\' AND password=\\'{password}\\'"
    )
    row = cur.execute(sql).fetchone()
    # EDIT-END: query
    if row:
        return {"id": row[0], "username": row[1], "is_admin": bool(row[2])}
    return None
'''


def _make_db_bank() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE,
        password TEXT, is_admin INTEGER DEFAULT 0
    )""")
    cur.executemany(
        "INSERT INTO users(username, password, is_admin) VALUES (?, ?, ?)",
        [("admin", "S3cr3t!Adm1n_Pa$$_4f8a91", 1),
         ("alice", "alice123", 0),
         ("bob",   "qwerty",   0)],
    )
    conn.commit()
    return conn


def _vulnerable_login(conn, username, password):
    cur = conn.cursor()
    sql = (
        "SELECT id, username, is_admin FROM users "
        f"WHERE username='{username}' AND password='{password}'"
    )
    try:
        row = cur.execute(sql).fetchone()
    except sqlite3.Error as exc:
        return {"error": str(exc)}
    if row:
        return {"id": row[0], "username": row[1], "is_admin": bool(row[2])}
    return None


def _handle_bank_login(method, path, headers, body, qs, u):
    if path in ("run", "run/") and method == "GET":
        return _render_bank_login("", u)
    if path == "run/login" and method == "POST":
        form = parse_form(body)
        conn = _make_db_bank()
        r = _vulnerable_login(conn, form.get("username", ""), form.get("password", ""))
        if isinstance(r, dict) and r.get("error"):
            return _render_bank_login(
                f'<div class="error"><b>SQL error:</b> '
                f'<code>{esc(r["error"])}</code></div>', u)
        if r is None:
            return _render_bank_login('<div class="error">Invalid credentials</div>', u)
        if r["is_admin"]:
            return _render_bank_success(r["username"], flag_for("sqli", u))
        return _render_bank_success(
            r["username"],
            "(вы вошли как обычный пользователь — флаг выдаётся только за admin)")
    return Resp.not_found()


def _render_bank_login(msg, u):
    content = f"""
      <span class="badge">Уязвимая лаборатория</span>
      <h1>SecureBank Login</h1>
      <p class="subtitle">Внутренний банковский портал</p>
      {msg}
      <form method="POST" action="login{u_qs(u)}">
        <label>Имя пользователя</label>
        <input type="text" name="username" autocomplete="off" required>
        <label>Пароль</label>
        <input type="password" name="password" autocomplete="off" required>
        <button type="submit" class="primary-full">Войти</button>
      </form>
      <div class="hint">Подсказка: debug-режим, SQL-ошибки видны в форме.</div>
    """
    return Resp.html(page("SecureBank — Вход", content))


def _render_bank_success(user, flag_text):
    content = f"""
      <h1>Здравствуйте, {esc(user)}</h1>
      <p class="subtitle">Аутентификация прошла успешно.</p>
      <div class="flag">{esc(flag_text)}</div>
      <p><a href="./">⟵ выйти</a></p>
    """
    return Resp.html(page("SecureBank — Успех", content))


def _check_bank_login(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "login")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция login(...).",
                "details": [{"ok": False, "msg": "Функция login не определена"}]}

    details: list[dict] = []
    args = [a.arg for a in fn.args.args]
    if args[:3] == ["conn", "username", "password"]:
        details.append({"ok": True, "msg": "Сигнатура login(conn, username, password) сохранена"})
    else:
        details.append({"ok": False, "msg": f"Изменена сигнатура login: {args}"})

    if has_fstring(fn):
        details.append({"ok": False, "msg": "Внутри login найдена f-строка — типичный источник SQLi"})
    else:
        details.append({"ok": True, "msg": "f-строк в login нет"})

    if has_format_call(fn):
        details.append({"ok": False, "msg": "Найден .format(...) — небезопасно для SQL"})
    else:
        details.append({"ok": True, "msg": "str.format() не используется"})

    if has_percent_format(fn):
        details.append({"ok": False, "msg": "Найдено %-форматирование — небезопасно для SQL"})
    else:
        details.append({"ok": True, "msg": "%-форматирование не используется"})

    if has_string_concat_with_name(fn, {"username", "password"}):
        details.append({"ok": False, "msg": "Конкатенация строки с username/password"})
    else:
        details.append({"ok": True, "msg": "Конкатенация с username/password отсутствует"})

    if calls_method_min_args(fn, "execute", 2):
        details.append({"ok": True, "msg": "Параметризованный execute(sql, params) найден"})
    else:
        details.append({"ok": False, "msg": "Нет execute(sql, params) — параметризация отсутствует"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены: SQL передаётся через параметры."
               if passed else
               "Решение не проходит проверки. Используйте execute(sql_с_?, (username, password)).")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Вариант B: user_lookup — численный ID, два правильных подхода
# =========================================================================

_TEMPLATE_USER_LOOKUP = '''"""
Поиск пользователя по числовому ID. Закройте SQL-инъекцию.
Менять можно ТОЛЬКО строки между маркерами EDIT-START / EDIT-END.

    conn    — sqlite3.Connection
    user_id — строка от пользователя (ожидается число)

Должна вернуть:
    {"id": int, "username": str, "is_admin": bool} — если найден
    None — если не найден или некорректный ввод
"""
import sqlite3


def find_user(conn, user_id):
    cur = conn.cursor()
    # EDIT-START: query
    sql = f"SELECT id, username, is_admin FROM users WHERE id={user_id}"
    row = cur.execute(sql).fetchone()
    # EDIT-END: query
    if row:
        return {"id": row[0], "username": row[1], "is_admin": bool(row[2])}
    return None
'''


def _make_db_users() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE,
        email TEXT, is_admin INTEGER DEFAULT 0
    )""")
    cur.executemany(
        "INSERT INTO users(id, username, email, is_admin) VALUES (?, ?, ?, ?)",
        [(1, "admin",  "admin@corp.local",  1),
         (2, "alice",  "alice@corp.local",  0),
         (3, "bob",    "bob@corp.local",    0),
         (7, "carol",  "carol@corp.local",  0)],
    )
    conn.commit()
    return conn


def _vulnerable_find(conn, user_id):
    cur = conn.cursor()
    # УЯЗВИМОСТЬ: ID подставляется без кавычек и без приведения типа
    sql = f"SELECT id, username, email, is_admin FROM users WHERE id={user_id}"
    try:
        row = cur.execute(sql).fetchone()
    except sqlite3.Error as exc:
        return {"error": str(exc)}
    if row:
        return {"id": row[0], "username": row[1], "email": row[2], "is_admin": bool(row[3])}
    return None


def _handle_user_lookup(method, path, headers, body, qs, u):
    if path in ("run", "run/") and method == "GET":
        # ID может передаваться через ?id=...
        uid = (qs.get("id") or [""])[0]
        if not uid:
            return _render_user_form("", "", u)
        conn = _make_db_users()
        r = _vulnerable_find(conn, uid)
        if isinstance(r, dict) and r.get("error"):
            return _render_user_form(
                uid,
                f'<div class="error"><b>SQL error:</b> '
                f'<code>{esc(r["error"])}</code></div>', u)
        if r is None:
            return _render_user_form(uid, '<div class="error">Пользователь не найден.</div>', u)

        # Найден. Если is_admin — флаг.
        info = (
            f'<div class="result">'
            f'<div><b>ID:</b> {r["id"]}</div>'
            f'<div><b>Логин:</b> {esc(r["username"])}</div>'
            f'<div><b>Email:</b> {esc(r["email"])}</div>'
            f'<div><b>Роль:</b> {"administrator" if r["is_admin"] else "user"}</div>'
            f'</div>'
        )
        if r["is_admin"]:
            info += f'<div class="flag">{esc(flag_for("sqli", u))}</div>'
        else:
            info += '<div class="hint">Это обычный пользователь. Флаг выдаётся только за admin.</div>'
        return _render_user_form(uid, info, u)
    return Resp.not_found()


def _render_user_form(uid, body_html, u):
    content = f"""
      <span class="badge">Уязвимая лаборатория</span>
      <h1>UserDB — поиск</h1>
      <p class="subtitle">Введите числовой ID пользователя.</p>
      <form method="GET" action=".">
        <label>ID пользователя</label>
        <input type="text" name="id" autocomplete="off" required value="{esc(uid)}">
        {'<input type="hidden" name="u" value="' + esc(u) + '">' if u else ''}
        <button type="submit" class="primary-full">Найти</button>
      </form>
      {body_html}
      <div class="hint">Подсказка: debug-режим, SQL-ошибки видны на странице.</div>
      <style>
        .result{{background:#0f172a;border:1px solid #334155;border-radius:8px;
                 padding:.9rem 1rem;margin:1rem 0;font-size:.92rem;line-height:1.7}}
        .result div b{{color:#cbd5e1}}
      </style>
    """
    return Resp.html(page("UserDB — Поиск", content))


def _check_user_lookup(code: str) -> dict:
    """Принимаются два решения: (а) параметризация execute, (б) int(user_id)."""
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "find_user")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция find_user(...).",
                "details": [{"ok": False, "msg": "Функция find_user не определена"}]}

    details: list[dict] = []
    args = [a.arg for a in fn.args.args]
    if args[:2] == ["conn", "user_id"]:
        details.append({"ok": True, "msg": "Сигнатура find_user(conn, user_id) сохранена"})
    else:
        details.append({"ok": False, "msg": f"Изменена сигнатура: {args}"})

    # Подход 1: параметризация
    has_param = calls_method_min_args(fn, "execute", 2)

    # Подход 2: явное приведение к int → int(user_id) где-то в коде
    has_int_cast = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "int"
                and n.args
                and isinstance(n.args[0], ast.Name)
                and n.args[0].id == "user_id"):
            has_int_cast = True
            break

    if has_param:
        details.append({"ok": True, "msg": "Параметризованный execute(sql, params) найден"})
    elif has_int_cast:
        details.append({"ok": True, "msg": "Найдено приведение int(user_id) — безопасно для числового ID"})
    else:
        details.append({"ok": False,
                        "msg": ("Ни параметризации (execute(sql, params)), "
                                "ни явного приведения int(user_id) — обе ветки решения отсутствуют")})

    # Дополнительная защита: если используется f-string, и нет int(user_id) — фейл
    if has_fstring(fn) and not has_int_cast and not has_param:
        details.append({"ok": False, "msg": "f-строка с user_id без защиты — небезопасно"})
    elif has_fstring(fn) and has_int_cast:
        details.append({"ok": True, "msg": "f-строка используется, но user_id приведён к int"})
    else:
        details.append({"ok": True, "msg": "f-строк с уязвимой подстановкой нет"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены."
               if passed else
               "Решение не проходит. Используйте параметризацию execute(sql, (user_id,)) "
               "ИЛИ явное приведение int(user_id) перед подстановкой.")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Dispatch по варианту
# =========================================================================

_TEMPLATES = {
    "bank_login":  _TEMPLATE_BANK_LOGIN,
    "user_lookup": _TEMPLATE_USER_LOOKUP,
}

_CHECKERS = {
    "bank_login":  _check_bank_login,
    "user_lookup": _check_user_lookup,
}

_HANDLERS = {
    "bank_login":  _handle_bank_login,
    "user_lookup": _handle_user_lookup,
}


def get_template(u: str = "") -> str:
    vname = variant_for("sqli", u, VARIANT_NAMES)
    return _TEMPLATES[vname]


def check(code: str, u: str = "") -> dict:
    vname = variant_for("sqli", u, VARIANT_NAMES)
    return _CHECKERS[vname](code)


def handle(method: str, path: str, headers: dict, body: bytes, qs: dict) -> Resp:
    u = get_u(qs)
    vname = variant_for("sqli", u, VARIANT_NAMES)
    return _HANDLERS[vname](method, path, headers, body, qs, u)


# Для обратной совместимости (если кто-то всё ещё читает TEMPLATE_SOURCE)
TEMPLATE_SOURCE = _TEMPLATE_BANK_LOGIN
