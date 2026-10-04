from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from core import ReconError, normalize_url, safe_json_loads
from safe_transport import perform_pinned_download, perform_pinned_request
from worker_scope import WORKER_CAPABILITIES, WORKER_SCOPE_VERSION, WorkerScopePolicy, task_scope_policy
from worker_results import classify_worker_result, worker_failure
from worker_artifacts import WORKER_ARTIFACT_VERSION, MAX_DOWNLOAD_BYTES, complete_download, download_limit, encode_artifact


MAX_REDIRECTS = 3


def _request(server: str, token: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    url=server.rstrip('/')+path
    data=json.dumps(payload).encode()
    req=urllib.request.Request(url,data=data,method='POST',headers={'Authorization':f'Bearer {token}','Content-Type':'application/json','User-Agent':'ReconMonitor-Worker/3.0'})
    with urllib.request.urlopen(req,timeout=30) as response:
        return safe_json_loads(response.read().decode(), {}, expected_type=dict)


def _headers_dict(headers: Any) -> dict[str,str]:
    try:
        return {str(k).lower():str(v) for k,v in headers.items()}
    except AttributeError:
        return {}


def _head_observation(
    method: str,
    url: str,
    status_code: int,
    headers: Any,
    _body: bytes,
    error: str = "",
) -> dict[str,Any]:
    return {
        "method":method,
        "url":url,
        "status_code":int(status_code or 0),
        "headers":_headers_dict(headers),
        "error":str(error or ""),
    }


def _execute_head(url: str, policy: WorkerScopePolicy) -> dict[str,Any]:
    current=url
    redirect_chain: list[str]=[]
    last: dict[str,Any]={}
    for redirect_index in range(MAX_REDIRECTS+1):
        result,transport_status=perform_pinned_request(
            {"method":"HEAD","url":current,"headers":{"User-Agent":"ReconMonitor-Worker/3.0"}},
            policy,
            safe_methods={"HEAD"},
            url_safety=lambda candidate, active_policy: (
                bool(active_policy.url_in_scope(candidate)),
                "outside_scope_or_invalid_url",
            ),
            observation=_head_observation,
            max_response_bytes=0,
            validation_version="worker-3.0",
        )
        last=dict(result)
        last["transport_status"]=transport_status
        headers=_headers_dict(last.get("headers",{}))
        location=str(headers.get("location","") or "").strip()
        status_code=int(last.get("status_code") or 0)
        if status_code in {301,302,303,307,308} and location:
            next_url=urllib.parse.urljoin(current,location)
            if not policy.url_in_scope(next_url):
                last["redirect_outside_scope"]=True
                last["error"]="redirect_outside_scope"
                last["transport_status"]="stopped_for_safety"
                break
            if redirect_index>=MAX_REDIRECTS:
                last["error"]="redirect_limit_exceeded"
                last["transport_status"]="stopped_for_safety"
                break
            redirect_chain.append(next_url)
            current=next_url
            continue
        break

    headers=_headers_dict(last.get("headers",{}))
    return {
        "url":normalize_url(current) or current,
        "status_code":int(last.get("status_code") or 0),
        "content_type":str(headers.get("content-type","")),
        "content_length":0,
        "truncated":False,
        "transport_status":str(last.get("transport_status") or "error"),
        "transport_error":str(last.get("error") or ""),
        "retry_after":str(headers.get("retry-after") or ""),
        "redirect_outside_scope":bool(last.get("redirect_outside_scope",False)),
        "redirect_chain":redirect_chain,
        "resolved_addresses":list(last.get("resolved_addresses") or []),
        "pinned_address":str(last.get("pinned_address") or ""),
        "dns_rebinding_protection":str(last.get("dns_rebinding_protection") or ""),
        "environment_proxy_used":bool(last.get("environment_proxy_used",False)),
    }


def _execute_download(url: str, policy: WorkerScopePolicy, max_bytes: int = MAX_DOWNLOAD_BYTES) -> dict[str,Any]:
    result=perform_pinned_download(
        url,
        policy,
        max_response_bytes=max_bytes,
        timeout=20,
        max_redirects=MAX_REDIRECTS,
        user_agent="ReconMonitor-Worker/3.0",
    )
    headers=_headers_dict(result.get("headers",{}))
    raw_data=result.get("data")
    data=raw_data if isinstance(raw_data,bytes) else b""
    error=str(result.get("error") or "")
    report = {
        "url":normalize_url(str(result.get("final_url") or url)) or str(result.get("final_url") or url),
        "status_code":int(result.get("status_code") or 0),
        "content_type":str(headers.get("content-type","")),
        "content_length":len(data),
        "content_range":str(headers.get("content-range") or ""),
        "etag":str(headers.get("etag") or ""),
        "last_modified":str(headers.get("last-modified") or ""),
        "truncated":error=="response_budget_exceeded",
        "transport_status":str(result.get("transport_status") or "error"),
        "transport_error":error,
        "retry_after":str(headers.get("retry-after") or ""),
        "redirect_outside_scope":bool(result.get("redirect_outside_scope",False)),
        "redirect_chain":[
            str(hop.get("next_url") or hop.get("url") or "")
            for hop in result.get("transport_hops",[])
            if isinstance(hop,dict)
        ],
        "resolved_addresses":list(result.get("resolved_addresses") or []),
        "pinned_address":str(result.get("pinned_address") or ""),
        "dns_rebinding_protection":str(result.get("dns_rebinding_protection") or ""),
        "environment_proxy_used":bool(result.get("environment_proxy_used",False)),
    }
    if report["transport_status"] == "ok" and 200 <= report["status_code"] < 300 and not error:
        if not isinstance(raw_data,bytes):
            report.update(transport_status="error",transport_error="Remote download body is missing")
        elif complete_download(report["status_code"],headers,data):
            report["artifact"]=encode_artifact(data)
        else:
            report.update(transport_status="stopped_for_safety",transport_error="incomplete_download",truncated=True)
    return report


def execute_task(payload: dict[str, Any]) -> dict[str, Any]:
    kind=str(payload.get('kind','')); url=str(payload.get('url',''))
    if kind not in WORKER_CAPABILITIES: raise ReconError(f'Unsupported remote task kind: {kind}')
    policy=task_scope_policy(payload)
    if not policy.url_in_scope(url): raise ReconError('Remote task URL is outside its declared scope policy')
    return _execute_head(url,policy) if kind=='http_head' else _execute_download(url,policy,download_limit(payload))


def run_worker(server: str, token: str, worker_id: str, name: str = '', interval: int = 5, once: bool = False) -> int:
    capabilities=list(WORKER_CAPABILITIES); name=name or socket.gethostname()
    registration=_request(server,token,'/api/v1/workers/register',{'worker_id':worker_id,'name':name,'capabilities':capabilities,'metadata':{'host':socket.gethostname(),'scope_policy_versions':[WORKER_SCOPE_VERSION],'download_artifact_versions':[WORKER_ARTIFACT_VERSION]}})
    worker_id=str(registration.get('worker_id') or worker_id)
    while True:
        _request(server,token,'/api/v1/workers/heartbeat',{'worker_id':worker_id})
        claimed=_request(server,token,'/api/v1/work/claim',{'worker_id':worker_id})
        if claimed.get('work') is None and not claimed.get('id'):
            if once:return 0
            time.sleep(max(1,interval));continue
        work=claimed
        lease_token=str(work.get('lease_token') or '')
        if not lease_token:
            raise ReconError('Remote work claim did not include a lease token')
        result=None
        try:
            payload=safe_json_loads(work.get('payload_json'), {}, expected_type=dict)
            result=execute_task(payload)
            outcome=classify_worker_result(payload,result)
        except ReconError as exc:
            outcome=worker_failure(str(exc),retry=False,reason='invalid_task')
        except Exception as exc:
            outcome=worker_failure(str(exc),retry=True)
        report={'id':work['id'],'worker_id':worker_id,'lease_token':lease_token,
                'ok':outcome.ok,'retry':outcome.retry,'error':outcome.error,'result':result}
        # A controller delivery error is not a failure of the target request.
        _request(server,token,'/api/v1/work/result',report)
        if once:return 0
