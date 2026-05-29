"""Лаба Path Traversal: file_read (проверка '..') vs avatar_serve (whitelist расширений или jail)."""
from __future__ import annotations

import ast
import posixpath

from .common import (
    LABS, Resp, esc, get_u, u_qs, flag_for, variant_for,
    parse_safe, find_function, contains_constant_string, calls_any_attr,
)


VARIANTS: dict[str, dict] = {
    "file_read":    {"label": "Path Traversal в просмотрщике файлов", "service": "DocViewer"},
    "avatar_serve": {"label": "Path Traversal в раздаче аватаров",    "service": "AvatarHost"},
}
VARIANT_NAMES = list(VARIANTS.keys())


def variant_meta(name: str) -> dict:
    cfg = VARIANTS.get(name) or VARIANTS[VARIANT_NAMES[0]]
    return {"name": name or VARIANT_NAMES[0], "label": cfg["label"]}


# =========================================================================
# Вариант A: file_read — проверка '..' и абсолютного пути
# =========================================================================

_TEMPLATE_FILE_READ = '''"""
Уязвимое чтение файла из публичной директории.

    base_dir — строка с базовой директорией, например '/srv/labs/files'
    filename — строка от пользователя

В namespace доступен модуль vfs:
    vfs.read(absolute_path) -> str | None

Должна вернуть содержимое файла ИЛИ None если запрос некорректный.
"""
import posixpath


def safe_read(base_dir, filename):
    # EDIT-START: read
    path = base_dir + "/" + filename
    return vfs.read(posixpath.normpath(path))
    # EDIT-END: read
'''


_VFS_FILES_A = {
    "welcome.txt":   "Добро пожаловать в DocViewer!",
    "manual.txt":    "Руководство пользователя.\nВыберите документ из списка.",
    "changelog.txt": "v1.2.0 — добавлен поиск\nv1.1.0 — улучшен интерфейс",
}


def _vfs_a(flag: str) -> dict[str, str]:
    fs = {f"/srv/labs/files/{n}": c for n, c in _VFS_FILES_A.items()}
    fs["/srv/labs/secret/flag.txt"] = flag
    fs["/srv/labs/secret/notes.txt"] = "заметки администратора"
    return fs


def _vulnerable_read_a(filename, fs):
    raw = "/srv/labs/files/" + filename
    canon = posixpath.normpath(raw).replace("\\", "/")
    return canon, fs.get(canon)


def _handle_file_read(method, path, headers, body, qs, u):
    if path not in ("run", "run/") or method != "GET":
        return Resp.not_found()
    fs = _vfs_a(flag_for("path_traversal", u))
    requested = (qs.get("file") or ["welcome.txt"])[0]
    canon, content = _vulnerable_read_a(requested, fs)

    if content is None:
        view = (
            '<div class="error">Файл не найден.</div>'
            f'<pre>resolved: {esc(canon)}</pre>'
        )
    else:
        view = (
            f'<div class="meta">📄 <b>{esc(requested)}</b> <span class="path">{esc(canon)}</span></div>'
            f'<pre>{esc(content)}</pre>'
        )
    if u:
        files = "\n".join(
            f'<li><a href="?file={esc(n)}&u={esc(u)}">{esc(n)}</a></li>'
            for n in sorted(_VFS_FILES_A.keys())
        )
    else:
        files = "\n".join(
            f'<li><a href="?file={esc(n)}">{esc(n)}</a></li>'
            for n in sorted(_VFS_FILES_A.keys())
        )
    return Resp.html(_PAGE_FILE.replace("{{FILES}}", files).replace("{{VIEW}}", view))


def _check_file_read(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "safe_read")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция safe_read(...).",
                "details": [{"ok": False, "msg": "Функция safe_read не определена"}]}
    details = []

    # Проверка на '..' в filename — должно быть упоминание ".." как константы
    rejects_dotdot = contains_constant_string(fn, "..")
    if rejects_dotdot:
        details.append({"ok": True, "msg": "Найдена проверка на '..' в имени файла"})
    else:
        details.append({"ok": False, "msg": "Нет проверки на '..' — выход из директории не блокируется"})

    # Проверка на абсолютный путь — startswith('/')
    rejects_absolute = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "startswith"
                and n.args
                and isinstance(n.args[0], ast.Constant)
                and isinstance(n.args[0].value, str)
                and "/" in n.args[0].value):
            rejects_absolute = True
    # Альтернатива: os.path.isabs
    if not rejects_absolute:
        if calls_any_attr(fn, {"isabs"}):
            rejects_absolute = True
    if rejects_absolute:
        details.append({"ok": True, "msg": "Найдена защита от абсолютных путей"})
    else:
        details.append({"ok": False, "msg": "Нет защиты от абсолютных путей (startswith('/') или os.path.isabs)"})

    if any(isinstance(n, ast.If) for n in ast.walk(fn)):
        details.append({"ok": True, "msg": "Условная ветка валидации найдена"})
    else:
        details.append({"ok": False, "msg": "Нет if — валидация не применяется"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены."
               if passed else
               "Решение не проходит. Отклоните filename, содержащий '..' или начинающийся с '/'.")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Вариант B: avatar_serve — whitelist расширений ИЛИ jail через abspath
# =========================================================================

_TEMPLATE_AVATAR = '''"""
Уязвимая раздача аватара пользователя.

    user_id  — целое число
    filename — имя файла от пользователя

В namespace доступен vfs.read(absolute_path).

База: /srv/avatars/{user_id}/{filename}

Должна вернуть содержимое файла ИЛИ None.
Допустимый формат: только .png и .jpg внутри директории своего user_id.
"""
import os
import posixpath


def serve_avatar(user_id, filename):
    # EDIT-START: read
    path = f"/srv/avatars/{user_id}/{filename}"
    return vfs.read(path)
    # EDIT-END: read
'''


_VFS_FILES_B = {
    "/srv/avatars/1/me.png":     "[binary png alice]",
    "/srv/avatars/1/old.jpg":    "[binary jpg alice old]",
    "/srv/avatars/2/bob.png":    "[binary png bob]",
    "/srv/admin/secret.txt":     "__FLAG__",
}


def _vfs_b(flag: str) -> dict[str, str]:
    fs = dict(_VFS_FILES_B)
    fs["/srv/admin/secret.txt"] = flag
    return fs


def _vulnerable_avatar(user_id, filename, fs):
    raw = f"/srv/avatars/{user_id}/{filename}"
    canon = posixpath.normpath(raw).replace("\\", "/")
    return canon, fs.get(canon)


def _handle_avatar(method, path, headers, body, qs, u):
    if path not in ("run", "run/") or method != "GET":
        return Resp.not_found()
    fs = _vfs_b(flag_for("path_traversal", u))
    user_id = (qs.get("user") or ["1"])[0]
    requested = (qs.get("file") or ["me.png"])[0]
    canon, content = _vulnerable_avatar(user_id, requested, fs)

    if content is None:
        view = (
            '<div class="error">Аватар не найден.</div>'
            f'<pre>resolved: {esc(canon)}</pre>'
        )
    else:
        view = (
            f'<div class="meta">🖼 <b>user={esc(user_id)}</b> <b>file={esc(requested)}</b> '
            f'<span class="path">{esc(canon)}</span></div>'
            f'<pre>{esc(content)}</pre>'
        )

    # подсказки в сайдбаре
    examples = [("1", "me.png"), ("1", "old.jpg"), ("2", "bob.png")]
    if u:
        links = "\n".join(
            f'<li><a href="?user={uid}&file={esc(f)}&u={esc(u)}">user={uid} · {esc(f)}</a></li>'
            for uid, f in examples
        )
    else:
        links = "\n".join(
            f'<li><a href="?user={uid}&file={esc(f)}">user={uid} · {esc(f)}</a></li>'
            for uid, f in examples
        )
    return Resp.html(_PAGE_AVATAR.replace("{{FILES}}", links).replace("{{VIEW}}", view))


def _check_avatar(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "serve_avatar")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция serve_avatar(...).",
                "details": [{"ok": False, "msg": "Функция serve_avatar не определена"}]}
    details = []

    # Подход 1: whitelist расширений через endswith
    has_endswith_ext = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "endswith"
                and n.args):
            arg = n.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("."):
                has_endswith_ext = True
            elif isinstance(arg, ast.Tuple):
                for elt in arg.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str) and elt.value.startswith("."):
                        has_endswith_ext = True

    # Подход 2: jail через abspath + startswith
    has_abspath = calls_any_attr(fn, {"abspath", "realpath"})
    has_startswith_dir = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "startswith"
                and n.args):
            arg = n.args[0]
            # Литеральная строка
            if (isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and "/srv/avatars" in arg.value):
                has_startswith_dir = True
            # f-string с подстрокой "/srv/avatars" в литеральных частях
            elif isinstance(arg, ast.JoinedStr):
                literal_parts = "".join(
                    p.value for p in arg.values
                    if isinstance(p, ast.Constant) and isinstance(p.value, str)
                )
                if "/srv/avatars" in literal_parts:
                    has_startswith_dir = True
    jail_approach = has_abspath and has_startswith_dir

    if has_endswith_ext:
        details.append({"ok": True, "msg": "Найден whitelist расширений через endswith('.png', '.jpg', ...)"})
    elif jail_approach:
        details.append({"ok": True,
                        "msg": "Найдена 'jail'-валидация: os.path.abspath/realpath + startswith('/srv/avatars/...')"})
    else:
        details.append({"ok": False,
                        "msg": ("Ни whitelist расширений (endswith), "
                                "ни jail через abspath+startswith — обе ветки решения отсутствуют")})

    # Защита от '..' в имени, на всякий случай
    rejects_dotdot = contains_constant_string(fn, "..")
    if has_endswith_ext and not rejects_dotdot:
        # Whitelist расширений сам по себе блокирует ".." потому что обычно ".." не оканчивается на .png
        # Но если студент проверяет endswith — атака `../admin/secret.txt` не имеет .png и не пройдёт
        details.append({"ok": True, "msg": "endswith-whitelist эффективно блокирует обходы '..'"})
    elif jail_approach:
        details.append({"ok": True, "msg": "jail через abspath блокирует обходы '..'"})
    elif rejects_dotdot:
        details.append({"ok": True, "msg": "Явная проверка на '..' найдена"})
    else:
        details.append({"ok": False, "msg": "Нет защиты от '..' в имени файла"})

    if any(isinstance(n, ast.If) for n in ast.walk(fn)):
        details.append({"ok": True, "msg": "Условная ветка валидации найдена"})
    else:
        details.append({"ok": False, "msg": "Нет if — валидация не применяется"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены."
               if passed else
               "Решение не проходит. Используйте whitelist расширений "
               "(filename.endswith(('.png','.jpg'))) ИЛИ jail "
               "(os.path.abspath(...).startswith('/srv/avatars/{user_id}/')).")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Dispatch
# =========================================================================

_TEMPLATES = {"file_read": _TEMPLATE_FILE_READ, "avatar_serve": _TEMPLATE_AVATAR}
_CHECKERS  = {"file_read": _check_file_read,    "avatar_serve": _check_avatar}
_HANDLERS  = {"file_read": _handle_file_read,   "avatar_serve": _handle_avatar}


def get_template(u: str = "") -> str:
    return _TEMPLATES[variant_for("path_traversal", u, VARIANT_NAMES)]


def check(code: str, u: str = "") -> dict:
    return _CHECKERS[variant_for("path_traversal", u, VARIANT_NAMES)](code)


def handle(method, path, headers, body, qs):
    u = get_u(qs)
    vname = variant_for("path_traversal", u, VARIANT_NAMES)
    return _HANDLERS[vname](method, path, headers, body, qs, u)


TEMPLATE_SOURCE = _TEMPLATE_FILE_READ


# =========================================================================
# HTML pages
# =========================================================================

_BASE_STYLE = """
<style>
 *{box-sizing:border-box}
 body{font-family:ui-sans-serif,system-ui,sans-serif;background:#0f172a;
   color:#e2e8f0;margin:0;min-height:100vh;padding:2rem}
 .wrap{max-width:880px;margin:0 auto;background:#1e293b;border:1px solid #334155;
   border-radius:16px;padding:2rem;box-shadow:0 20px 60px rgba(0,0,0,.5)}
 .head{margin-bottom:1rem}
 h1{margin:0 0 .25rem;font-size:1.5rem}
 .sub{color:#94a3b8;font-size:.9rem;margin:0 0 1rem}
 .badge{display:inline-block;padding:.2rem .6rem;border-radius:999px;background:#ef4444;
   color:white;font-size:.7rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
   margin-bottom:.5rem}
 .layout{display:grid;grid-template-columns:200px 1fr;gap:1rem}
 .sidebar{background:#0f172a;border:1px solid #334155;border-radius:10px;padding:.8rem}
 .sidebar h3{margin:0 0 .4rem;font-size:.85rem;color:#cbd5e1;text-transform:uppercase;letter-spacing:.05em}
 .sidebar ul{list-style:none;padding:0;margin:0}
 .sidebar li{margin-bottom:.25rem}
 .sidebar a{color:#93c5fd;text-decoration:none;font-size:.88rem}
 .sidebar a:hover{text-decoration:underline}
 .view{min-height:200px}
 .meta{font-size:.85rem;color:#cbd5e1;margin-bottom:.6rem}
 .meta b{color:#e2e8f0}
 .path{color:#64748b;font-family:ui-monospace,monospace;font-size:.8rem;margin-left:.5rem}
 pre{background:#020617;border:1px solid #1e293b;border-radius:8px;padding:1rem;
   font-family:ui-monospace,monospace;font-size:.85rem;color:#86efac;line-height:1.5;
   white-space:pre-wrap;word-break:break-all;margin:0}
 .error{background:rgba(239,68,68,0.15);border:1px solid #ef4444;color:#fca5a5;
   padding:.75rem;border-radius:8px;font-size:.9rem;margin-bottom:.6rem}
 .hint{margin-top:1rem;padding:.6rem .9rem;background:rgba(59,130,246,.1);
   border:1px solid rgba(59,130,246,.3);border-radius:8px;font-size:.85rem;color:#93c5fd}
</style>
"""

_PAGE_FILE = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DocViewer</title>{_BASE_STYLE}</head>
<body>
<div class="wrap">
  <div class="head">
    <span class="badge">Уязвимая лаборатория</span>
    <h1>📁 DocViewer</h1>
    <p class="sub">Просмотр публичных документов из <code>/srv/labs/files/</code></p>
  </div>
  <div class="layout">
    <div class="sidebar"><h3>Документы</h3><ul>{{{{FILES}}}}</ul></div>
    <div class="view">{{{{VIEW}}}}</div>
  </div>
  <div class="hint">💡 Имя файла передаётся через <code>?file=…</code>. А что если попробовать <code>../</code>?</div>
</div>
</body></html>"""

_PAGE_AVATAR = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AvatarHost</title>{_BASE_STYLE}</head>
<body>
<div class="wrap">
  <div class="head">
    <span class="badge">Уязвимая лаборатория</span>
    <h1>🖼 AvatarHost</h1>
    <p class="sub">Раздача аватаров пользователей из <code>/srv/avatars/&lt;user_id&gt;/&lt;file&gt;</code></p>
  </div>
  <div class="layout">
    <div class="sidebar"><h3>Примеры</h3><ul>{{{{FILES}}}}</ul></div>
    <div class="view">{{{{VIEW}}}}</div>
  </div>
  <div class="hint">💡 Параметры <code>?user=…&amp;file=…</code>. Где-то рядом лежит <code>/srv/admin/secret.txt</code>.</div>
</div>
</body></html>"""
