"""Reversible, named input transformations; never execute target-supplied code."""
from __future__ import annotations
import base64
import html
import json
import urllib.parse

ENCODINGS = {'url', 'html_entities', 'base64', 'json', 'js_unicode'}
DEFAULT_ENCODINGS = [[], ['url'], ['url', 'url'], ['html_entities'], ['html_entities', 'html_entities'], ['base64'], ['json'], ['js_unicode'], ['html_entities', 'base64', 'url']]


def encode(value: str, chain: list[str]) -> str:
    for name in chain:
        if name == 'url': value = urllib.parse.quote(value, safe='')
        elif name == 'html_entities': value = ''.join('&#x' + format(ord(c), 'x') + ';' for c in value)
        elif name == 'base64': value = base64.b64encode(value.encode()).decode()
        elif name == 'json': value = json.dumps(value, ensure_ascii=True)
        elif name == 'js_unicode': value = ''.join('\\u' + format(ord(c), '04x') for c in value)
        else: raise ValueError('Unknown XSS encoding')
    return value


def carries(url: str, body: str, value: str) -> bool:
    if not value: return False
    values = [url, body]
    values.extend(v for _, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))
    values.extend(v for _, v in urllib.parse.parse_qsl(body, keep_blank_values=True))
    try:
        def strings(item):
            if isinstance(item, str): yield item
            elif isinstance(item, list):
                for v in item: yield from strings(v)
            elif isinstance(item, dict):
                for v in item.values(): yield from strings(v)
        values.extend(strings(json.loads(body)))
    except (ValueError, TypeError): pass
    return any(value in v for v in values)


def reflected(body: str, value: str) -> bool:
    return bool(value and any(v in body for v in (value, json.dumps(value, ensure_ascii=True)[1:-1], html.escape(value, quote=True))))
