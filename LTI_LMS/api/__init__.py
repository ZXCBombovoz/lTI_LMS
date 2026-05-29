"""Лабораторные работы.

Eager-импорты ниже нужны Vercel-трейсеру: только увидев их, он включает
файлы в bundle серверлес-функции. БЕЗ этих строк он не находит файлы
idor/cmdi/path_traversal в /var/task.

Если какой-то из импортов падает на рантайме — ошибка пробрасывается
в api/index.py и видна через /labs/_debug.
"""
from . import common  # noqa: F401
from . import sqli  # noqa: F401
from . import xss  # noqa: F401
from . import idor  # noqa: F401
from . import cmdi  # noqa: F401
from . import path_traversal  # noqa: F401
