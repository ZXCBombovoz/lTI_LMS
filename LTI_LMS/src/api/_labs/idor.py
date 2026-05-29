"""Лаба IDOR: два варианта — явная проверка владельца vs игнорирование переданного id."""
from __future__ import annotations

import ast

from .common import (
    LABS, Resp, esc, get_u, u_qs, flag_for, variant_for,
    parse_safe, find_function, compares_attribute,
)


VARIANTS: dict[str, dict] = {
    "note":    {"label": "IDOR в просмотре заметок", "service": "NoteVault"},
    "balance": {"label": "IDOR в банковском балансе", "service": "PocketBank"},
}
VARIANT_NAMES = list(VARIANTS.keys())


def variant_meta(name: str) -> dict:
    cfg = VARIANTS.get(name) or VARIANTS[VARIANT_NAMES[0]]
    return {"name": name or VARIANT_NAMES[0], "label": cfg["label"]}


# =========================================================================
# Вариант A: note — проверка владельца
# =========================================================================

_TEMPLATE_NOTE = '''"""
Уязвимый просмотр заметки — IDOR.

    notes        — словарь {id: {"owner": str, "title": str, "body": str}}
    current_user — имя залогиненного пользователя
    note_id      — id запрошенной заметки

Должна вернуть:
    dict заметки — если current_user имеет к ней доступ
    None         — если доступ запрещён или заметки нет
"""


def get_note(notes, current_user, note_id):
    # EDIT-START: access
    return notes.get(note_id)
    # EDIT-END: access
'''


_NOTES = {
    1:  {"id": 1,  "owner": "alice", "title": "Список покупок",      "body": "Молоко, хлеб, кофе"},
    2:  {"id": 2,  "owner": "alice", "title": "Идеи для проекта",    "body": "1) рефакторинг, 2) тесты, 3) релиз"},
    3:  {"id": 3,  "owner": "alice", "title": "TODO на неделю",      "body": "митинг, отчёт, обновить документацию"},
    17: {"id": 17, "owner": "bob",   "title": "Личное",              "body": "не для чужих глаз"},
    42: {"id": 42, "owner": "bob",   "title": "Резервные коды",      "body": "Backup recovery code: __FLAG__"},
    99: {"id": 99, "owner": "carol", "title": "Заметка",              "body": "ничего интересного"},
}


def _handle_note(method, path, headers, body, qs, u):
    if path in ("run", "run/") and method == "GET":
        return _index_note(u)
    if path.startswith("run/note/") and method == "GET":
        try:
            nid = int(path[len("run/note/"):])
        except ValueError:
            return _view_note(None, u)
        return _view_note(_NOTES.get(nid), u)
    return Resp.not_found()


def _index_note(u):
    own = sorted(
        (n for n in _NOTES.values() if n["owner"] == "alice"),
        key=lambda n: n["id"],
    )
    rows = "\n".join(
        f'<a class="row" href="note/{n["id"]}{u_qs(u)}">'
        f'<span class="id">#{n["id"]}</span>'
        f'<span class="title">{esc(n["title"])}</span>'
        f'</a>'
        for n in own
    )
    body = _PAGE_NOTE_INDEX.replace("{{NOTES}}", rows)
    return Resp.html(body)


def _view_note(note, u):
    if note is None:
        return Resp.html(_render_note("Не найдено", "—", "—", "<i>Такой заметки нет.</i>", u))
    text = note["body"]
    if note["id"] == 42:
        text = text.replace("__FLAG__", flag_for("idor", u))
    return Resp.html(_render_note(
        esc(note["title"]), esc(note["owner"]), str(note["id"]), esc(text), u
    ))


def _render_note(title, owner, id_, body, u):
    return (
        _PAGE_NOTE_VIEW
        .replace("{{TITLE}}", title)
        .replace("{{OWNER}}", owner)
        .replace("{{ID}}", id_)
        .replace("{{BODY}}", body)
        .replace("{{U}}", u_qs(u))
    )


def _check_note(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "get_note")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция get_note(...).",
                "details": [{"ok": False, "msg": "Функция get_note не определена"}]}
    details = []

    # Должна быть проверка владельца: note['owner'] == current_user или note.owner == current_user
    owner_check = False
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare):
            operands = [n.left, *n.comparators]
            mentions_owner = False
            mentions_current = False
            for op in operands:
                # note['owner'] or note.get('owner') or note.owner
                if isinstance(op, ast.Subscript) and isinstance(op.slice, ast.Constant) and op.slice.value == "owner":
                    mentions_owner = True
                if isinstance(op, ast.Attribute) and op.attr == "owner":
                    mentions_owner = True
                if (isinstance(op, ast.Call)
                        and isinstance(op.func, ast.Attribute)
                        and op.func.attr == "get"
                        and op.args
                        and isinstance(op.args[0], ast.Constant)
                        and op.args[0].value == "owner"):
                    mentions_owner = True
                if isinstance(op, ast.Name) and op.id == "current_user":
                    mentions_current = True
            if mentions_owner and mentions_current:
                owner_check = True

    if owner_check:
        details.append({"ok": True, "msg": "Найдено сравнение владельца заметки с current_user"})
    else:
        details.append({"ok": False, "msg": "Нет проверки note['owner'] == current_user"})

    # Должна быть условная ветка
    if any(isinstance(n, ast.If) for n in ast.walk(fn)):
        details.append({"ok": True, "msg": "Условная ветка контроля доступа найдена"})
    else:
        details.append({"ok": False, "msg": "Нет if — проверка доступа не применяется"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены: владелец сверяется с current_user."
               if passed else
               "Решение не проходит. Сравните note['owner'] с current_user и верните None для чужих.")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Вариант B: balance — игнорировать переданный account_id
# =========================================================================

_TEMPLATE_BALANCE = '''"""
Уязвимый просмотр банковского баланса — IDOR.

    accounts     — словарь {account_id: {"owner": str, "balance": int, "secret": str}}
    current_user — имя залогиненного пользователя
    account_id   — id запрошенного счёта (приходит из URL)

Должна вернуть:
    dict счёта — если current_user имеет к нему доступ
    None       — если доступ запрещён или счёта нет

Подсказка: account_id приходит от пользователя и не должен определять,
чьи данные мы вернём. Доступ определяется по current_user.
"""


def get_balance(accounts, current_user, account_id):
    # EDIT-START: access
    return accounts.get(account_id)
    # EDIT-END: access
'''


_ACCOUNTS = {
    "1001": {"id": "1001", "owner": "alice", "balance": 12500, "secret": "ничего интересного"},
    "1002": {"id": "1002", "owner": "alice", "balance":  3200, "secret": "ничего интересного"},
    "2042": {"id": "2042", "owner": "bob",   "balance": 75000, "secret": "Recovery: __FLAG__"},
    "2099": {"id": "2099", "owner": "bob",   "balance":   500, "secret": "ничего интересного"},
    "3001": {"id": "3001", "owner": "carol", "balance": 18000, "secret": "ничего интересного"},
}


def _handle_balance(method, path, headers, body, qs, u):
    if path in ("run", "run/") and method == "GET":
        return _index_balance(u)
    if path.startswith("run/account/") and method == "GET":
        acc_id = path[len("run/account/"):]
        return _view_balance(_ACCOUNTS.get(acc_id), u)
    return Resp.not_found()


def _index_balance(u):
    own = sorted(
        (a for a in _ACCOUNTS.values() if a["owner"] == "alice"),
        key=lambda a: a["id"],
    )
    rows = "\n".join(
        f'<a class="row" href="account/{a["id"]}{u_qs(u)}">'
        f'<span class="id">№ {a["id"]}</span>'
        f'<span class="bal">{a["balance"]:,} ₽</span>'
        f'</a>'
        for a in own
    )
    body = _PAGE_BAL_INDEX.replace("{{ROWS}}", rows)
    return Resp.html(body)


def _view_balance(acc, u):
    if acc is None:
        return Resp.html(_render_balance("—", "—", "—", "<i>Такого счёта нет.</i>", u))
    secret = acc["secret"]
    if acc["id"] == "2042":
        secret = secret.replace("__FLAG__", flag_for("idor", u))
    return Resp.html(_render_balance(
        esc(acc["id"]), esc(acc["owner"]), f'{acc["balance"]:,} ₽', esc(secret), u
    ))


def _render_balance(acc_id, owner, balance, secret, u):
    return (
        _PAGE_BAL_VIEW
        .replace("{{ID}}", acc_id)
        .replace("{{OWNER}}", owner)
        .replace("{{BAL}}", balance)
        .replace("{{SECRET}}", secret)
        .replace("{{U}}", u_qs(u))
    )


def _check_balance(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "get_balance")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция get_balance(...).",
                "details": [{"ok": False, "msg": "Функция get_balance не определена"}]}
    details = []

    # current_user должен быть упомянут в теле функции (без него access control невозможен)
    uses_current = any(
        isinstance(n, ast.Name) and n.id == "current_user"
        for n in ast.walk(fn)
    )
    if uses_current:
        details.append({"ok": True, "msg": "current_user используется в логике"})
    else:
        details.append({"ok": False,
                        "msg": "current_user не используется — без него access control невозможен"})

    # Подход 1: явное сравнение account.owner == current_user
    owner_check = False
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare):
            ops = [n.left, *n.comparators]
            has_owner = False
            has_current = False
            for op in ops:
                if isinstance(op, ast.Subscript) and isinstance(op.slice, ast.Constant) and op.slice.value == "owner":
                    has_owner = True
                if isinstance(op, ast.Attribute) and op.attr == "owner":
                    has_owner = True
                if (isinstance(op, ast.Call)
                        and isinstance(op.func, ast.Attribute)
                        and op.func.attr == "get"
                        and op.args
                        and isinstance(op.args[0], ast.Constant)
                        and op.args[0].value == "owner"):
                    has_owner = True
                if isinstance(op, ast.Name) and op.id == "current_user":
                    has_current = True
            if has_owner and has_current:
                owner_check = True

    # Подход 2: account_id не используется как ключ (например, итерация по accounts)
    # Признаки: есть for/dict comprehension по accounts, без accounts[account_id]
    uses_account_id_key = False
    for n in ast.walk(fn):
        if isinstance(n, ast.Subscript):
            # accounts[account_id]
            if (isinstance(n.value, ast.Name) and n.value.id == "accounts"
                    and isinstance(n.slice, ast.Name) and n.slice.id == "account_id"):
                uses_account_id_key = True
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "get"
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "accounts"
                and n.args
                and isinstance(n.args[0], ast.Name)
                and n.args[0].id == "account_id"):
            uses_account_id_key = True

    iter_over_accounts = any(
        isinstance(n, ast.For)
        and isinstance(n.iter, (ast.Name, ast.Call, ast.Attribute))
        for n in ast.walk(fn)
    )

    ignores_account_id = (not uses_account_id_key) and iter_over_accounts and uses_current

    if owner_check:
        details.append({"ok": True, "msg": "Найдено сравнение account['owner'] == current_user"})
    elif ignores_account_id:
        details.append({"ok": True,
                        "msg": "account_id не используется как ключ; данные берутся итерацией по current_user"})
    else:
        details.append({"ok": False,
                        "msg": ("Ни явной проверки account['owner'] == current_user, "
                                "ни игнорирования account_id (с итерацией по current_user)")})

    if any(isinstance(n, ast.If) for n in ast.walk(fn)) or iter_over_accounts:
        details.append({"ok": True, "msg": "Логика фильтрации найдена (if или итерация)"})
    else:
        details.append({"ok": False, "msg": "Нет ни if, ни цикла — фильтрация невозможна"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены."
               if passed else
               "Решение не проходит. Проверьте account['owner'] == current_user "
               "ИЛИ не используйте account_id вообще — итерируйтесь по accounts и выбирайте по current_user.")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Dispatch
# =========================================================================

_TEMPLATES = {"note": _TEMPLATE_NOTE, "balance": _TEMPLATE_BALANCE}
_CHECKERS  = {"note": _check_note,    "balance": _check_balance}
_HANDLERS  = {"note": _handle_note,   "balance": _handle_balance}


def get_template(u: str = "") -> str:
    return _TEMPLATES[variant_for("idor", u, VARIANT_NAMES)]


def check(code: str, u: str = "") -> dict:
    return _CHECKERS[variant_for("idor", u, VARIANT_NAMES)](code)


def handle(method, path, headers, body, qs):
    u = get_u(qs)
    vname = variant_for("idor", u, VARIANT_NAMES)
    return _HANDLERS[vname](method, path, headers, body, qs, u)


TEMPLATE_SOURCE = _TEMPLATE_NOTE


# =========================================================================
# HTML pages
# =========================================================================

_BASE_STYLE = """
<style>
 *{box-sizing:border-box}
 body{font-family:ui-sans-serif,system-ui,sans-serif;
   background:#0f172a;color:#e2e8f0;margin:0;min-height:100vh;padding:2rem}
 .card{max-width:640px;margin:0 auto;background:#1e293b;border:1px solid #334155;
   border-radius:16px;padding:2rem;box-shadow:0 20px 60px rgba(0,0,0,.5)}
 h1{margin:0 0 .25rem;font-size:1.5rem;display:flex;align-items:center;gap:.6rem}
 .badge{display:inline-block;padding:.2rem .6rem;border-radius:999px;background:#ef4444;
   color:white;font-size:.7rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase}
 .me{font-size:.85rem;color:#94a3b8;margin-bottom:1.5rem}
 .me b{color:#cbd5e1}
 .row{display:flex;align-items:center;gap:1rem;padding:.85rem 1rem;
   background:#0f172a;border:1px solid #334155;border-radius:10px;text-decoration:none;
   color:#e2e8f0;margin-bottom:.5rem;transition:all .15s}
 .row:hover{border-color:#3b82f6;transform:translateX(2px)}
 .id{color:#64748b;font-family:ui-monospace,monospace;font-size:.85rem;min-width:5rem}
 .title{font-weight:500}
 .bal{margin-left:auto;font-family:ui-monospace,monospace;color:#86efac}
 .meta{display:flex;gap:1rem;font-size:.85rem;color:#94a3b8;margin-bottom:1rem}
 .meta b{color:#cbd5e1}
 .body{background:#0f172a;border:1px solid #334155;border-radius:10px;padding:1rem;
   white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:.9rem;line-height:1.6}
 a.back{display:inline-block;color:#93c5fd;margin-bottom:1rem;text-decoration:none;font-size:.9rem}
 a.back:hover{text-decoration:underline}
 .hint{margin-top:1rem;padding:.75rem 1rem;background:rgba(59,130,246,.1);
   border:1px solid rgba(59,130,246,.3);border-radius:8px;font-size:.85rem;color:#93c5fd}
</style>
"""

_PAGE_NOTE_INDEX = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NoteVault</title>{_BASE_STYLE}</head>
<body><div class="card">
  <span class="badge">Уязвимая лаборатория</span>
  <h1>📓 NoteVault</h1>
  <div class="me">Вы вошли как <b>alice</b> · Личные заметки</div>
  {{{{NOTES}}}}
  <div class="hint">💡 Каждая заметка имеет числовой id. А что если поменять его в URL?</div>
</div></body></html>"""

_PAGE_NOTE_VIEW = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{{{TITLE}}}} — NoteVault</title>{_BASE_STYLE}</head>
<body><div class="card">
  <a class="back" href="../{{{{U}}}}">⟵ Назад к списку</a>
  <span class="badge">Уязвимая лаборатория</span>
  <h1>{{{{TITLE}}}}</h1>
  <div class="meta"><span>id: <b>{{{{ID}}}}</b></span><span>владелец: <b>{{{{OWNER}}}}</b></span></div>
  <div class="body">{{{{BODY}}}}</div>
</div></body></html>"""

_PAGE_BAL_INDEX = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PocketBank</title>{_BASE_STYLE}</head>
<body><div class="card">
  <span class="badge">Уязвимая лаборатория</span>
  <h1>🏦 PocketBank</h1>
  <div class="me">Вы вошли как <b>alice</b> · Ваши счета</div>
  {{{{ROWS}}}}
  <div class="hint">💡 Номер счёта подставляется в URL. А что если ввести чужой номер?</div>
</div></body></html>"""

_PAGE_BAL_VIEW = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Счёт {{{{ID}}}} — PocketBank</title>{_BASE_STYLE}</head>
<body><div class="card">
  <a class="back" href="../{{{{U}}}}">⟵ Назад к счетам</a>
  <span class="badge">Уязвимая лаборатория</span>
  <h1>Счёт № {{{{ID}}}}</h1>
  <div class="meta">
    <span>владелец: <b>{{{{OWNER}}}}</b></span>
    <span>баланс: <b>{{{{BAL}}}}</b></span>
  </div>
  <div class="body">{{{{SECRET}}}}</div>
</div></body></html>"""
