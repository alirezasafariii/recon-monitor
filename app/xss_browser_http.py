"""HTTP entity/text decoding for browser evidence, without changing page semantics."""
from __future__ import annotations
import codecs
import gzip
import io
import re
import zlib
from core import ReconError

VERSION = '1.0.0'


def decode_entity(raw: bytes, content_encoding: str, check=lambda: None) -> bytes:
    for coding in reversed([c.strip().lower() for c in content_encoding.split(',') if c.strip()]):
        check()
        if coding == 'identity':continue
        if coding in {'gzip','x-gzip'}:
            chunks=[]
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                while True:
                    check()
                    chunk=stream.read1(64*1024)
                    if not chunk:break
                    chunks.append(chunk)
            raw=b''.join(chunks)
        elif coding == 'deflate':
            try:raw=_inflate(raw,zlib.MAX_WBITS,check)
            except zlib.error:raw=_inflate(raw,-zlib.MAX_WBITS,check)
        elif coding == 'br':
            try:import brotli
            except ImportError:raise ReconError('response_encoding_br_unavailable') from None
            raw=brotli.decompress(raw)
        else:raise ReconError('unsupported_response_content_encoding')
        check()
    return raw


def _inflate(raw,window,check):
    decoder=zlib.decompressobj(window)
    chunks=[]
    while True:
        check()
        chunk=decoder.decompress(raw,64*1024)
        chunks.append(chunk)
        raw=decoder.unconsumed_tail
        if not raw and len(chunk)<64*1024:break
    if not decoder.eof:raise zlib.error('Incomplete compressed response')
    return b''.join(chunks)+decoder.flush()


def decode_text(raw: bytes, headers) -> tuple[str,str]:
    if raw.startswith(codecs.BOM_UTF8):encoding='utf-8-sig'
    elif raw.startswith((codecs.BOM_UTF32_LE,codecs.BOM_UTF32_BE)):encoding='utf-32'
    elif raw.startswith((codecs.BOM_UTF16_LE,codecs.BOM_UTF16_BE)):encoding='utf-16'
    else:
        encoding=headers.get_content_charset()
        if not encoding and headers.get_content_type()=='text/html':
            # HTML's early charset declaration window; this is not a response quota.
            match=re.search(br'charset\s*=\s*["\x27]?\s*([a-zA-Z0-9_-]+)',raw[:1024],re.I)
            encoding=match.group(1).decode('ascii') if match else 'windows-1252'
        encoding=encoding or 'utf-8'
    try:canonical=codecs.lookup(encoding).name
    except LookupError:canonical='utf-8'
    return raw.decode(canonical,errors='replace'),canonical
