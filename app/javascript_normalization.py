"""Conservative JavaScript fingerprints without executing or parsing target code."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


JS_NORMALIZATION_VERSION = 1
_LINE_TERMINATORS = frozenset("\r\n\u2028\u2029")
_WHITE_SPACE = frozenset("\t\v\f \u00a0\ufeff\u1680\u202f\u205f\u3000" + "".join(chr(i) for i in range(0x2000, 0x200B)))
_TOKEN = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*"
    r"|0[xX][0-9A-Fa-f_]+n?|0[bB][01_]+n?|0[oO][0-7_]+n?"
    r"|(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9][0-9_]*)?n?"
    r"|\?\.(?![0-9])|>>>=|===|!==|\*\*=|&&=|\|\|=|\?\?=|>>=|\.\.\."
    r"|=>|==|!=|>=|\+\+|--|\*\*|>>|&&|\|\||\?\?|[+*%&|^\-]="
    r"|[{}()\[\].;,>+*%&|^!~?:=\-]"
)


@dataclass(frozen=True)
class JavaScriptNormalization:
    text: str
    fingerprint: str
    mode: str
    reason: str = ""


def _result(text: str, mode: str, reason: str = "", *, raw_bytes: bytes | None = None) -> JavaScriptNormalization:
    data = raw_bytes if raw_bytes is not None else text.encode("utf-8", "replace")
    return JavaScriptNormalization(text, hashlib.sha256(data).hexdigest(), mode, reason)


def normalize_javascript(text: str) -> JavaScriptNormalization:
    """Normalize a lexical subset; preserve the whole input when a parser is needed.

    Slash goals (division versus regex), templates and JSX cannot be resolved
    safely by a context-free lexer. No partial normalization survives a fallback.
    Line terminators between tokens remain significant for semicolon insertion.
    """
    parts: list[str] = []
    index = 0
    line_break = False
    while index < len(text):
        char = text[index]
        if char in _WHITE_SPACE or char in _LINE_TERMINATORS:
            line_break |= char in _LINE_TERMINATORS
            index += 1
            continue
        if text.startswith("//", index):
            index += 2
            while index < len(text) and text[index] not in _LINE_TERMINATORS:
                index += 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                return _result(text, "raw_fallback", "unterminated_comment")
            line_break |= any(c in _LINE_TERMINATORS for c in text[index + 2:end])
            index = end + 2
            continue
        if char in "'\"":
            start = index
            quote = char
            index += 1
            while index < len(text):
                char = text[index]
                if char == "\\":
                    index += 2
                    if index <= len(text) and text[index - 1:index + 1] == "\r\n":
                        index += 1
                elif char == quote:
                    index += 1
                    break
                elif char in "\r\n":
                    return _result(text, "raw_fallback", "invalid_string_line_break")
                else:
                    index += 1
            else:
                return _result(text, "raw_fallback", "unterminated_string")
            token = text[start:index]
        else:
            if char in "/`<":
                reason = {"/": "slash_requires_parser", "`": "template_requires_parser", "<": "syntax_requires_parser"}[char]
                return _result(text, "raw_fallback", reason)
            match = _TOKEN.match(text, index)
            if match is None:
                return _result(text, "raw_fallback", "unsupported_token")
            token = match.group()
            index = match.end()
        if parts:
            parts.append("\n" if line_break else " ")
        parts.append(token)
        line_break = False
    return _result("".join(parts), "tokens")


def normalize_javascript_bytes(data: bytes) -> JavaScriptNormalization:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _result(data.decode("utf-8", "replace"), "raw_fallback", "invalid_utf8", raw_bytes=data)
    return normalize_javascript(text)
