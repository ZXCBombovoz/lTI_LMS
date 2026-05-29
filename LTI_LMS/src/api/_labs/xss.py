"""Лаба XSS: два варианта с разными задачами и решениями."""
from __future__ import annotations

import ast
import re

from .common import (
    LABS, Resp, esc, page, parse_form, parse_cookies, get_u, u_qs,
    flag_for, variant_for, sign_state, verify_state,
    parse_safe, find_function, calls_any_attr, calls_method_min_args,
    imports_module,
)


# =========================================================================

VARIANTS: dict[str, dict] = {
    "comment": {
        "label": "Stored XSS в комментарии",
        "service": "FeedbackBoard",
    },
    "link":    {
        "label": "XSS через javascript-URL",
        "service": "QuickLinks",
    },
}
VARIANT_NAMES = list(VARIANTS.keys())


def variant_meta(name: str) -> dict:
    cfg = VARIANTS.get(name) or VARIANTS[VARIANT_NAMES[0]]
    return {"name": name or VARIANT_NAMES[0], "label": cfg["label"]}


# =========================================================================
# Вариант A: comment — Stored XSS, решение через html.escape
# =========================================================================

_TEMPLATE_COMMENT = '''"""
Уязвимое отображение комментария — Stored XSS.

    author, text — строки от пользователя

Должна вернуть HTML-строку для безопасного отображения.
"""
import html


def render_comment(author, text):
    # EDIT-START: render
    return f"<div><b>{author}</b>: {text}</div>"
    # EDIT-END: render
'''

_COOKIE_C = "lab_xss_comments"
_XSS_RE = re.compile(
    r'(<script\b|onerror\s*=|onload\s*=|onclick\s*=|<img\s+[^>]*src|javascript:)', re.I
)


def _looks_xss(text: str) -> bool:
    return bool(_XSS_RE.search(text or ""))


def _load_comments(headers: dict) -> list[list[str]]:
    cookies = parse_cookies(headers.get("cookie"))
    state = verify_state(cookies.get(_COOKIE_C))
    if state and isinstance(state.get("c"), list):
        return state["c"][-20:]
    return [
        ["Администратор", "Добро пожаловать! Делитесь мыслями в комментариях."],
        ["alice", "Отличная статья, спасибо!"],
    ]


def _save_c(comments: list[list[str]]) -> str:
    return sign_state({"c": comments[-20:]})


def _handle_comment(method, path, headers, body, qs, u):
    comments = _load_comments(headers)
    if path in ("run", "run/") and method == "GET":
        return _render_comment(comments, u)
    if path == "run/comment" and method == "POST":
        form = parse_form(body)
        a = (form.get("author") or "Аноним")[:50]
        t = (form.get("text") or "")[:1000]
        if t.strip():
            comments = comments + [[a, t]]
        resp = Resp.redirect(f"./{u_qs(u)}")
        resp.headers.append((
            "Set-Cookie",
            f"{_COOKIE_C}={_save_c(comments)}; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax"
        ))
        return resp
    if path == "run/reset" and method == "POST":
        resp = Resp.redirect(f"./{u_qs(u)}")
        resp.headers.append((
            "Set-Cookie",
            f"{_COOKIE_C}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        ))
        return resp
    return Resp.not_found()


def _render_comment(comments, u):
    parts = []
    detected = False
    for a, t in comments:
        if _looks_xss(t):
            detected = True
        # УЯЗВИМОСТЬ: text НЕ экранируется
        parts.append(
            f'<div class="comment">'
            f'<div class="author">{esc(a)}</div>'
            f'<div class="text">{t}</div>'
            f'</div>'
        )
    flag_block = ""
    if detected:
        flag_block = (
            f'<div class="flag-banner">'
            f'<b>XSS-атака зарегистрирована!</b><br>'
            f'<span class="flag">{esc(flag_for("xss", u))}</span>'
            f'</div>'
        )
    body = (
        _PAGE_COMMENT
        .replace("{{COMMENTS}}", "\n".join(parts))
        .replace("{{FLAG}}", flag_block)
        .replace("{{U}}", u_qs(u))
    )
    return Resp.html(body)


def _check_comment(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "render_comment")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция render_comment(...).",
                "details": [{"ok": False, "msg": "Функция render_comment не определена"}]}
    details: list[dict] = []

    # Подход 1: html.escape
    used_html = imports_module(tree, "html") and calls_any_attr(fn, {"escape"})

    # Подход 2: цепочка replace с экранированием < и >
    replaces = 0
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "replace"
                and len(n.args) >= 2
                and isinstance(n.args[0], ast.Constant)
                and isinstance(n.args[1], ast.Constant)):
            if n.args[0].value in ("<", ">", "&", '"', "'"):
                replaces += 1
    used_replace_chain = replaces >= 2  # хотя бы < и >

    if used_html:
        details.append({"ok": True, "msg": "Использован html.escape() — корректный путь"})
    elif used_replace_chain:
        details.append({"ok": True, "msg": "Использована цепочка .replace() с экранированием HTML-символов"})
    else:
        details.append({"ok": False,
                        "msg": "Ни html.escape(), ни .replace('<','&lt;').replace('>','&gt;') не найдены"})

    # Проверка: в return-выражении не должно быть прямой подстановки text без экранирования
    # упрощённо: ищем f-string с прямым именем text
    raw_text_in_fstring = False
    for n in ast.walk(fn):
        if isinstance(n, ast.JoinedStr):
            for v in n.values:
                if isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) and v.value.id == "text":
                    raw_text_in_fstring = True
    if raw_text_in_fstring and not (used_html or used_replace_chain):
        details.append({"ok": False, "msg": "В f-строке подставляется raw text без экранирования"})
    else:
        details.append({"ok": True, "msg": "Сырого text в f-строке без экранирования нет"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены: HTML экранируется."
               if passed else
               "Решение не проходит. Экранируйте text через html.escape(text) перед подстановкой.")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Вариант B: link — XSS через javascript: URL, решение через валидацию URL
# =========================================================================

_TEMPLATE_LINK = '''"""
Уязвимое отображение ссылки — DOM XSS через javascript: URL.

    url, text — строки от пользователя

Должна вернуть безопасную HTML-строку с ссылкой.
Если URL небезопасен — вернуть тег без href (или span с текстом).
"""
import html


def render_link(url, text):
    # EDIT-START: render
    return f'<a href="{url}">{text}</a>'
    # EDIT-END: render
'''

_COOKIE_L = "lab_xss_links"


def _load_links(headers: dict) -> list[list[str]]:
    cookies = parse_cookies(headers.get("cookie"))
    state = verify_state(cookies.get(_COOKIE_L))
    if state and isinstance(state.get("l"), list):
        return state["l"][-20:]
    return [
        ["https://example.com", "Пример сайта"],
        ["https://mtuci.ru",   "МТУСИ — официальный сайт"],
    ]


def _save_l(links: list[list[str]]) -> str:
    return sign_state({"l": links[-20:]})


_JS_URL_RE = re.compile(r'^\s*javascript\s*:', re.I)


def _looks_xss_url(url: str) -> bool:
    return bool(_JS_URL_RE.match(url or ""))


def _handle_link(method, path, headers, body, qs, u):
    links = _load_links(headers)
    if path in ("run", "run/") and method == "GET":
        return _render_link(links, u)
    if path == "run/add" and method == "POST":
        form = parse_form(body)
        url_v = (form.get("url") or "").strip()[:500]
        text_v = (form.get("text") or "").strip()[:200]
        if url_v and text_v:
            links = links + [[url_v, text_v]]
        resp = Resp.redirect(f"./{u_qs(u)}")
        resp.headers.append((
            "Set-Cookie",
            f"{_COOKIE_L}={_save_l(links)}; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax"
        ))
        return resp
    if path == "run/reset" and method == "POST":
        resp = Resp.redirect(f"./{u_qs(u)}")
        resp.headers.append((
            "Set-Cookie",
            f"{_COOKIE_L}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        ))
        return resp
    return Resp.not_found()


def _render_link(links, u):
    parts = []
    detected = False
    for url_v, text_v in links:
        if _looks_xss_url(url_v):
            detected = True
        # УЯЗВИМОСТЬ: url подставляется в href как есть
        parts.append(
            f'<li class="link"><a href="{esc(url_v)}">{esc(text_v)}</a></li>'
        )
    flag_block = ""
    if detected:
        flag_block = (
            f'<div class="flag-banner">'
            f'<b>XSS-атака зарегистрирована — javascript: URL!</b><br>'
            f'<span class="flag">{esc(flag_for("xss", u))}</span>'
            f'</div>'
        )
    body = (
        _PAGE_LINK
        .replace("{{LINKS}}", "\n".join(parts))
        .replace("{{FLAG}}", flag_block)
        .replace("{{U}}", u_qs(u))
    )
    return Resp.html(body)


def _check_link(code: str) -> dict:
    tree = parse_safe(code)
    if tree is None:
        return {"passed": False, "summary": "Синтаксическая ошибка.", "details": []}
    fn = find_function(tree, "render_link")
    if fn is None:
        return {"passed": False, "summary": "Не найдена функция render_link(...).",
                "details": [{"ok": False, "msg": "Функция render_link не определена"}]}
    details: list[dict] = []

    # Подход: проверка url.startswith(...) с http/https
    starts_with_http = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "startswith"
                and n.args):
            arg = n.args[0]
            # startswith("https://") или startswith(("http://", "https://"))
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.lower().startswith(("http://", "https://")):
                    starts_with_http = True
            elif isinstance(arg, ast.Tuple):
                for elt in arg.elts:
                    if (isinstance(elt, ast.Constant)
                            and isinstance(elt.value, str)
                            and elt.value.lower().startswith(("http://", "https://"))):
                        starts_with_http = True

    # Альтернатива: использование urllib.parse.urlparse и проверка scheme
    uses_urlparse = False
    if imports_module(tree, "urllib.parse") or imports_module(tree, "urllib"):
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute) and n.func.attr == "urlparse":
                    uses_urlparse = True
                elif isinstance(n.func, ast.Name) and n.func.id == "urlparse":
                    uses_urlparse = True

    if starts_with_http:
        details.append({"ok": True, "msg": "Найдена проверка url.startswith('http://') / 'https://'"})
    elif uses_urlparse:
        details.append({"ok": True, "msg": "Используется urllib.parse.urlparse() для разбора схемы"})
    else:
        details.append({"ok": False,
                        "msg": ("Нет валидации URL: ни startswith('http(s)://'), "
                                "ни urlparse() — javascript: пройдёт")})

    # Должно быть какое-то условие (if) — без условия валидация не работает
    has_if = any(isinstance(n, ast.If) for n in ast.walk(fn))
    if has_if:
        details.append({"ok": True, "msg": "Условная ветка валидации найдена"})
    else:
        details.append({"ok": False, "msg": "Нет условия (if) — валидация не применяется"})

    passed = all(d["ok"] for d in details)
    summary = ("Все проверки пройдены: javascript: URL блокируется."
               if passed else
               "Решение не проходит. Проверьте, что url начинается с http:// или https:// "
               "перед подстановкой в href.")
    return {"passed": passed, "summary": summary, "details": details}


# =========================================================================
# Dispatch
# =========================================================================

_TEMPLATES = {"comment": _TEMPLATE_COMMENT, "link": _TEMPLATE_LINK}
_CHECKERS  = {"comment": _check_comment,  "link": _check_link}
_HANDLERS  = {"comment": _handle_comment, "link": _handle_link}


def get_template(u: str = "") -> str:
    return _TEMPLATES[variant_for("xss", u, VARIANT_NAMES)]


def check(code: str, u: str = "") -> dict:
    return _CHECKERS[variant_for("xss", u, VARIANT_NAMES)](code)


def handle(method, path, headers, body, qs):
    u = get_u(qs)
    vname = variant_for("xss", u, VARIANT_NAMES)
    return _HANDLERS[vname](method, path, headers, body, qs, u)


TEMPLATE_SOURCE = _TEMPLATE_COMMENT


# =========================================================================
# HTML pages
# =========================================================================

_PAGE_COMMENT = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FeedbackBoard · Стенд XSS</title>
<style>
 *{box-sizing:border-box}
 body{font-family:ui-sans-serif,system-ui,sans-serif;background:#0f172a;
   color:#e2e8f0;margin:0;min-height:100vh;padding:2rem}
 .wrap{max-width:680px;margin:0 auto;background:#1e293b;border:1px solid #334155;
   border-radius:16px;padding:2rem;box-shadow:0 20px 60px rgba(0,0,0,.5)}
 h1{margin:0 0 .25rem;font-size:1.5rem}
 h2{margin:.5rem 0 0;font-size:1.1rem;color:#cbd5e1}
 .badge{display:inline-block;padding:.2rem .6rem;border-radius:999px;background:#ef4444;
   color:white;font-size:.7rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
   margin-bottom:.5rem}
 .article{padding:1rem;background:#0f172a;border-radius:10px;margin:1rem 0 1.5rem;
   color:#cbd5e1;font-size:.92rem;line-height:1.55}
 .comment{padding:.8rem 1rem;background:#0f172a;border:1px solid #334155;border-radius:10px;
   margin-bottom:.6rem;font-size:.9rem;line-height:1.5}
 .comment .author{font-weight:600;color:#3b82f6;margin-bottom:.2rem;font-size:.85rem}
 form{margin-top:1rem;display:flex;flex-direction:column;gap:.5rem}
 input[type=text],textarea{width:100%;padding:.6rem .8rem;background:#020617;
   border:1px solid #334155;color:#e2e8f0;border-radius:6px;font-size:.9rem;
   font-family:inherit}
 textarea{resize:vertical}
 button{padding:.6rem 1.2rem;background:#3b82f6;color:white;border:0;border-radius:6px;
   font-weight:600;font-size:.9rem;cursor:pointer;align-self:flex-start}
 button:hover{background:#2563eb}
 .reset-form{margin-top:.5rem}
 .reset-form button{background:#475569;font-size:.8rem;padding:.4rem .8rem}
 .reset-form button:hover{background:#334155}
 .flag-banner{margin:1rem 0;padding:1rem;background:#064e3b;border:2px dashed #10b981;
   border-radius:8px;color:#6ee7b7;text-align:center}
 .flag{font-family:ui-monospace,monospace;font-size:1.05rem;display:block;margin-top:.4rem}
 .hint{margin-top:1rem;padding:.6rem .9rem;background:rgba(59,130,246,.1);
   border:1px solid rgba(59,130,246,.3);border-radius:8px;font-size:.85rem;color:#93c5fd}
</style></head>
<body>
<div class="wrap">
  <span class="badge">Уязвимая лаборатория</span>
  <h1>FeedbackBoard</h1>
  <h2>Отзывы посетителей</h2>
  <div class="article">Это страница отзывов. Текст комментариев публикуется как есть.</div>
  {{FLAG}}
  <div class="comments">{{COMMENTS}}</div>
  <form method="POST" action="comment{{U}}">
    <input type="text" name="author" placeholder="Имя" required maxlength="50">
    <textarea name="text" placeholder="Ваш комментарий" required rows="3" maxlength="1000"></textarea>
    <button type="submit">Опубликовать</button>
  </form>
  <form class="reset-form" method="POST" action="reset{{U}}">
    <button type="submit">Сбросить комментарии</button>
  </form>
  <div class="hint">💡 Попробуйте теги <code>&lt;script&gt;</code>, <code>&lt;img onerror=&gt;</code>.</div>
</div>
</body></html>"""


_PAGE_LINK = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuickLinks · Стенд XSS</title>
<style>
 *{box-sizing:border-box}
 body{font-family:ui-sans-serif,system-ui,sans-serif;background:#0f172a;
   color:#e2e8f0;margin:0;min-height:100vh;padding:2rem}
 .wrap{max-width:680px;margin:0 auto;background:#1e293b;border:1px solid #334155;
   border-radius:16px;padding:2rem;box-shadow:0 20px 60px rgba(0,0,0,.5)}
 h1{margin:0 0 .25rem;font-size:1.5rem}
 .badge{display:inline-block;padding:.2rem .6rem;border-radius:999px;background:#ef4444;
   color:white;font-size:.7rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
   margin-bottom:.5rem}
 .subtitle{color:#94a3b8;font-size:.9rem;margin-bottom:1rem}
 ul.links{list-style:none;padding:0;margin:1rem 0}
 ul.links li.link{padding:.6rem .9rem;background:#0f172a;border:1px solid #334155;
   border-radius:10px;margin-bottom:.4rem}
 ul.links li.link a{color:#93c5fd;text-decoration:none}
 ul.links li.link a:hover{text-decoration:underline}
 form{margin-top:1rem;display:flex;flex-direction:column;gap:.5rem}
 input[type=text]{width:100%;padding:.6rem .8rem;background:#020617;
   border:1px solid #334155;color:#e2e8f0;border-radius:6px;font-size:.9rem;
   font-family:inherit}
 button{padding:.6rem 1.2rem;background:#3b82f6;color:white;border:0;border-radius:6px;
   font-weight:600;font-size:.9rem;cursor:pointer;align-self:flex-start}
 button:hover{background:#2563eb}
 .reset-form{margin-top:.5rem}
 .reset-form button{background:#475569;font-size:.8rem;padding:.4rem .8rem}
 .reset-form button:hover{background:#334155}
 .flag-banner{margin:1rem 0;padding:1rem;background:#064e3b;border:2px dashed #10b981;
   border-radius:8px;color:#6ee7b7;text-align:center}
 .flag{font-family:ui-monospace,monospace;font-size:1.05rem;display:block;margin-top:.4rem}
 .hint{margin-top:1rem;padding:.6rem .9rem;background:rgba(59,130,246,.1);
   border:1px solid rgba(59,130,246,.3);border-radius:8px;font-size:.85rem;color:#93c5fd}
</style></head>
<body>
<div class="wrap">
  <span class="badge">Уязвимая лаборатория</span>
  <h1>🔖 QuickLinks</h1>
  <p class="subtitle">Сохраняйте полезные ссылки в один клик.</p>
  {{FLAG}}
  <ul class="links">{{LINKS}}</ul>
  <form method="POST" action="add{{U}}">
    <input type="text" name="url" placeholder="URL (например https://example.com)" required maxlength="500">
    <input type="text" name="text" placeholder="Подпись" required maxlength="200">
    <button type="submit">Сохранить</button>
  </form>
  <form class="reset-form" method="POST" action="reset{{U}}">
    <button type="submit">Сбросить ссылки</button>
  </form>
  <div class="hint">💡 Попробуйте сохранить ссылку с протоколом <code>javascript:</code> и кликнуть.</div>
</div>
</body></html>"""
