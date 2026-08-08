from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from core import ReconError, normalize_host, normalize_url, safe_json_loads


def _request(server: str, token: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    url=server.rstrip('/')+path
    data=json.dumps(payload).encode()
    req=urllib.request.Request(url,data=data,method='POST',headers={'Authorization':f'Bearer {token}','Content-Type':'application/json','User-Agent':'ReconMonitor-Worker/3.0'})
    with urllib.request.urlopen(req,timeout=30) as response:
        return safe_json_loads(response.read().decode(), {}, expected_type=dict)


def _host_allowed(url: str, roots: list[str]) -> bool:
    normalized=normalize_url(url)
    if not normalized:return False
    host=normalize_host(urllib.parse.urlsplit(normalized).hostname or '')
    return any(host==normalize_host(root) or host.endswith('.'+normalize_host(root)) for root in roots)


def execute_task(payload: dict[str, Any]) -> dict[str, Any]:
    kind=str(payload.get('kind','')); url=str(payload.get('url','')); roots=[str(x) for x in payload.get('allowed_roots',[])]
    if kind not in {'http_head','download_url'}: raise ReconError(f'Unsupported remote task kind: {kind}')
    if not _host_allowed(url,roots): raise ReconError('Remote task URL is outside its declared roots')
    method='HEAD' if kind=='http_head' else 'GET'; headers={'User-Agent':'ReconMonitor-Worker/3.0'}
    if method=='GET': headers['Range']='bytes=0-1048575'
    req=urllib.request.Request(url,method=method,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=20) as response:
            data=response.read(1024*1024+1) if method=='GET' else b''
            return {'url':normalize_url(response.geturl()) or url,'status_code':int(response.status or 0),'content_type':str(response.headers.get('Content-Type','')),'content_length':len(data),'truncated':len(data)>1024*1024}
    except urllib.error.HTTPError as exc:
        return {'url':url,'status_code':int(exc.code),'content_type':str(exc.headers.get('Content-Type','')) if exc.headers else '', 'http_error':True}


def run_worker(server: str, token: str, worker_id: str, name: str = '', interval: int = 5, once: bool = False) -> int:
    capabilities=['http_head','download_url']; name=name or socket.gethostname()
    registration=_request(server,token,'/api/v1/workers/register',{'worker_id':worker_id,'name':name,'capabilities':capabilities,'metadata':{'host':socket.gethostname()}})
    worker_id=str(registration.get('worker_id') or worker_id)
    while True:
        _request(server,token,'/api/v1/workers/heartbeat',{'worker_id':worker_id})
        claimed=_request(server,token,'/api/v1/work/claim',{'worker_id':worker_id,'capabilities':capabilities})
        if claimed.get('work') is None and not claimed.get('id'):
            if once:return 0
            time.sleep(max(1,interval));continue
        work=claimed
        try:
            payload=safe_json_loads(work.get('payload_json'), {}, expected_type=dict)
            result=execute_task(payload)
            _request(server,token,'/api/v1/work/result',{'id':work['id'],'ok':True,'result':result})
        except Exception as exc:
            _request(server,token,'/api/v1/work/result',{'id':work.get('id',0),'ok':False,'error':str(exc),'retry':True})
        if once:return 0
