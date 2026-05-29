"""Лаба Command Injection: ping (список аргументов) vs backup (whitelist символов)."""
from __future__ import annotations

import ast
import re

from .common import (
    LABS, Resp, esc, page, parse_form, get_u, u_qs, flag_for, variant_for,
    parse_safe, find_function, passes_list_to_call,
    has_fstring, has_format_call, calls_any_attr, imports_module,
)


VARIANTS: dict[str, dict] = {
    "ping":   {"label": "Command Injection в ping",   "service": "NetTools"},
    "backup": {"label": "Command Injection в backup", "service": "FileBackup"},
}
VARIANT_NAMES = list(VARIANTS.keys())


def variant_meta(name: str) -> dict:
    cfg = VARIANTS.get(name) or VARIANTS[VARIANT_NAMES[0]]
    return {"name": name or VARIANT_NAMES[0], "label": cfg["label"]}


# =========================================================================
# Fake shell (общий, ping/cat/ls/etc.)
# =========================================================================

_PING_RE = re.compile(r"^\s*ping\s+(?:-c\s+\d+\s+)?(?P<host>[A-Za-z0-9.\-_]+)\s*$")
_CP_RE   = re.compile(r"^\s*cp\s+(?P<src>\S+)\s+(?P<dst>\S+)\s*$")
_CAT_RE  = re.compile(r"^\s*cat\s+(?P<path>\S+)(?:\s+\S+)*\s*$")
_LS_RE   = re.compile(r"^\s*ls\s*(?P<path>\S+)?\s*$")
_ID_RE   = re.compile(r"^\s*(id|whoami|uname(?:\s+-a)?)\s*$")
_ECHO_RE = re.compile(r"^\s*echo\s+(?P<msg>.*)\s*$")
_PWD_RE  = re.compile(r"^\s*pwd\s*$")


def _run_one(cmd: str, fs: dict[str, str]) -> str:
    if (m := _PING_RE.match(cmd)):
        h = m.group("host")
        return (
            f"PING {h} (93.184.216.34) 56(84) bytes of data.\n"
            f"64 bytes from {h}: icmp_seq=1 ttl=56 time=12.4 ms\n"
            f"--- {h} ping statistics ---\n"
            f"1 packets transmitted, 1 received, 0% loss\n"
        )
    if (m := _CP_RE.match(cmd)):
        src = m.group("src")
        if src in fs:
            return f"'{src}' -> '{m.group('dst')}'"
        return f"cp: cannot stat '{src}': No such file or directory"
    if (m := _CAT_RE.match(cmd)):
        path = m.group("path")
        return fs.get(path, f"cat: {path}: No such file or directory")
    if (m := _LS_RE.match(cmd)):
        return "\n".join(sorted({k.split("/")[1] for k in fs if "/" in k[1:]}))
    if _ID_RE.match(cmd):
        if cmd.strip() == "whoami": return "labuser"
        if cmd.strip().startswith("uname"): return "Linux lab-sandbox 5.15.0 #1 SMP x86_64"
        return "uid=1000(labuser) gid=1000(labuser)"
    if _PWD_RE.match(cmd):
        return "/home/labuser"
    if (m := _ECHO_RE.match(cmd)):
        return m.group("msg")
    parts = cmd.split()
    return f"sh: 1: {parts[0] if parts else cmd}: command not found"


def _run_fake_shell(cmd: str, flag: str) -> str:
    fs = {
        "/etc/lab_flag": flag,
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nlabuser:x:1000:1000::/home/labuser:/bin/bash",
        "/var/files/notes.txt": "important data",
    }
    pieces = re.split(r"\s*(?:&&|\|\||;|\|)\s*", cmd)
    outs = []
    for p in pieces:
        p = p.strip()
        if p:
            outs.append(_run_one(p, fs))
    return "\n".join(outs)


# =========================================================================
# Вариант A: ping — список аргументов
# =========================================================================

_TEMPLATE_PING = '''"""
Уязвимая утилита ping. Закройте Command Injection.

    host — имя хоста от пользователя

Должна вернуть строку с выводом команды.
"""
import subprocess


def run_ping(host):
    # EDIT-START: command
    cmd = f"ping -c 1 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    return result.stdout
    # EDIT-END: command
'''


def _handle_ping(method, path, headers, body, qs, u):
    if path in ("run", "run/") and method == "GET":
        return _render_ping("", "", u)
    if path == "run/ping" and method == "POST":
        form = parse_form(body)
        host = (form.get("host") or "").strip()[:200]
        if not host:
            return _render_ping("<i>Введите имя хоста.</i>", "", u)
        cmd = f"ping -c 1 {host}"
        try:
            raw = _run_fake_shell(cmd, flag_for("cmdi", u))
        except Exception as e:
            raw = f"error: {type(e).__name__}: {e}"
        return _render_ping(f"<pre>{esc(raw)}</pre>", host, u)
    return Resp.not_found()


def _render_ping(output, host, u):
    content = f"""
      <span class="badge">Уязвимая лаборатория</span>
      <h1>🛰 NetTools — Ping</h1>
      <p class="subtitle">Проверка доступности хоста через системную команду ping.</p>
      <form method="POST" action="ping{u_qs(u)}" style="display:flex;gap:.5rem">
        <input type="text" name="host" placeholder="example.com" autocomplete="off"
               value="{esc(host)}" required style="flex:1">
        <button type="submit">Ping</button>
      </form>
      {output}
      <div class="hint">💡 Внутри лаб-окружения существует файл <code>/etc/lab_flag</code>.</div>
    """
    return Resp.html(page("NetTools — Ping", content))


def _check_ping(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "run_ping")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция run_ping(...).",
                "details": [{"ok": False, "msg": "Функция run_ping не определена"}]}
    details = []

    if has_fstring(fn) or has_format_call(fn):
        details.append({"ok": False, "msg": "В функции остались f-строки/format — host попадает в shell-команду"})
    else:
        details.append({"ok": True, "msg": "f-строк/format со склейкой команды нет"})

    list_arg = passes_list_to_call(fn, "run") or passes_list_to_call(fn, "Popen") or passes_list_to_call(fn, "check_output")
    if list_arg:
        details.append({"ok": True, "msg": "subprocess вызывается со списком аргументов (без shell)"})
    else:
        details.append({"ok": False, "msg": "subprocess не вызывается со списком аргументов"})

    # shell=False либо отсутствует shell=True
    shell_true = False
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            for kw in n.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_true = True
    if shell_true:
        details.append({"ok": False, "msg": "shell=True — пользовательский ввод интерпретируется как shell"})
    else:
        details.append({"ok": True, "msg": "shell=True не используется"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены."
               if passed else
               "Решение не проходит. Передайте аргументы списком: subprocess.run(['ping','-c','1',host])")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Вариант B: backup — whitelist символов через re.match
# =========================================================================

_TEMPLATE_BACKUP = '''"""
Уязвимое резервное копирование файла. Закройте Command Injection.

    filename — имя файла от пользователя

Должна вернуть строку с выводом команды копирования.
Если имя файла содержит недопустимые символы — вернуть строку об ошибке.

Допустимый формат имени: буквы, цифры, точка, подчёркивание, дефис.
Никаких слешей, пробелов, точек с запятой, пайпов и т.п.
"""
import subprocess
import re


def backup_file(filename):
    # EDIT-START: command
    cmd = f"cp /var/files/{filename} /backups/"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    return result.stdout
    # EDIT-END: command
'''


def _handle_backup(method, path, headers, body, qs, u):
    if path in ("run", "run/") and method == "GET":
        return _render_backup("", "", u)
    if path == "run/backup" and method == "POST":
        form = parse_form(body)
        fname = (form.get("filename") or "").strip()[:200]
        if not fname:
            return _render_backup("<i>Введите имя файла.</i>", "", u)
        cmd = f"cp /var/files/{fname} /backups/"
        try:
            raw = _run_fake_shell(cmd, flag_for("cmdi", u))
        except Exception as e:
            raw = f"error: {type(e).__name__}: {e}"
        return _render_backup(f"<pre>{esc(raw)}</pre>", fname, u)
    return Resp.not_found()


def _render_backup(output, fname, u):
    content = f"""
      <span class="badge">Уязвимая лаборатория</span>
      <h1>💾 FileBackup</h1>
      <p class="subtitle">Резервное копирование файла из <code>/var/files/</code>.</p>
      <form method="POST" action="backup{u_qs(u)}" style="display:flex;gap:.5rem">
        <input type="text" name="filename" placeholder="notes.txt" autocomplete="off"
               value="{esc(fname)}" required style="flex:1">
        <button type="submit">Backup</button>
      </form>
      {output}
      <div class="hint">💡 Внутри лаб-окружения существует файл <code>/etc/lab_flag</code>.</div>
    """
    return Resp.html(page("FileBackup", content))


def _check_backup(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "backup_file")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция backup_file(...).",
                "details": [{"ok": False, "msg": "Функция backup_file не определена"}]}
    details = []

    # Подход 1: subprocess со списком аргументов
    list_arg = passes_list_to_call(fn, "run") or passes_list_to_call(fn, "Popen") or passes_list_to_call(fn, "check_output")

    # Подход 2: whitelist через re.match/re.fullmatch
    has_re_match = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in {"match", "fullmatch"}
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "re"):
            has_re_match = True

    # Подход 3 (как часть подхода 2): проверка через .isalnum() / .replace() — учитываем как валидацию
    has_validation_method = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in {"isalnum", "isalpha", "isdigit"}):
            has_validation_method = True

    # Должна быть хотя бы одна стратегия защиты
    if list_arg:
        details.append({"ok": True, "msg": "subprocess вызывается со списком аргументов (без shell)"})
    elif has_re_match:
        details.append({"ok": True, "msg": "Найдена валидация через re.match/re.fullmatch (whitelist)"})
    elif has_validation_method:
        details.append({"ok": True, "msg": "Найдена валидация через isalnum/isalpha"})
    else:
        details.append({"ok": False,
                        "msg": ("Ни списка аргументов в subprocess, ни re.match-валидации, "
                                "ни isalnum-проверки")})

    # Должно быть условие или return - валидация без проверки бесполезна
    has_branch = any(isinstance(n, (ast.If, ast.Return)) for n in ast.walk(fn))
    if has_branch:
        details.append({"ok": True, "msg": "Ветка проверки/возврата найдена"})
    else:
        details.append({"ok": False, "msg": "Нет if/return — валидация не применяется"})

    # shell=True с f-string очень плохо
    shell_true = False
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            for kw in n.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_true = True
    if shell_true and not has_re_match and not list_arg and not has_validation_method:
        details.append({"ok": False, "msg": "shell=True без валидации — небезопасно"})
    else:
        details.append({"ok": True, "msg": "Опасной комбинации shell=True без валидации нет"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены."
               if passed else
               "Решение не проходит. Используйте либо список аргументов "
               "(subprocess.run(['cp', f'/var/files/{filename}', '/backups/'])), "
               "либо whitelist через re.fullmatch(r'[A-Za-z0-9._-]+', filename).")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Dispatch
# =========================================================================

_TEMPLATES = {"ping": _TEMPLATE_PING, "backup": _TEMPLATE_BACKUP}
_CHECKERS  = {"ping": _check_ping,    "backup": _check_backup}
_HANDLERS  = {"ping": _handle_ping,   "backup": _handle_backup}


def get_template(u: str = "") -> str:
    return _TEMPLATES[variant_for("cmdi", u, VARIANT_NAMES)]


def check(code: str, u: str = "") -> dict:
    return _CHECKERS[variant_for("cmdi", u, VARIANT_NAMES)](code)


def handle(method, path, headers, body, qs):
    u = get_u(qs)
    vname = variant_for("cmdi", u, VARIANT_NAMES)
    return _HANDLERS[vname](method, path, headers, body, qs, u)


TEMPLATE_SOURCE = _TEMPLATE_PING
