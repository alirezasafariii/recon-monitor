from __future__ import annotations

"""Dedicated API/configuration analyzers for OWASP expansion phase 1.

These analyzers interpret stored target evidence only. They never run load,
concurrency, business-transaction, configuration-change, scope-expansion, or
third-party probing actions.
"""

import re
from typing import Any, Iterable, Mapping
from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, observations, scalar, truth, header_map
from .owasp_expansion_common import controlled_observation


def _yes(d: Mapping[str, Any], key: str) -> bool: return truth(d.get(key)) is True

def _result(analyzer, family, variant, support, contradict, taxonomy, method, fp, writeups, direct, rules, summary, base, **meta):
    if not support and not contradict: return None
    return finalize_result(analyzer=analyzer,family=family,variant=variant,support=support,contradict=contradict,taxonomy=taxonomy,methodology=method,false_positive_checks=fp,writeup_patterns=writeups,direct_types=set(direct),rule_ids=rules,summary=summary,base=base,extra_meta=meta)

RESOURCE_TAX={"owasp":["API4:2023 Unrestricted Resource Consumption"],"wstg":["WSTG-BUSL-05"],"cwe":["CWE-770","CWE-400"],"capec":[]}
RESOURCE_DIRECT=("resource_limit_not_enforced","unbounded_batch_accepted","cost_amplification_observed")
RESOURCE_BLOCK=("rate_limit_enforced","pagination_limit_enforced","upload_size_limit_enforced","execution_timeout_enforced","batch_limit_enforced","cost_quota_enforced")
def analyze_unrestricted_resource_consumption_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",body_fields:Iterable[str]=(),query_fields:Iterable[str]=(),path_fields:Iterable[str]=(),details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="")->dict[str,Any]|None:
    del db,analysis_id,target,business_context; d=dict(details or {}); support=[]; contradict=[]
    text=" ".join([endpoint,semantic_text," ".join(map(str,[*body_fields,*query_fields,*path_fields]))]).lower()
    if _yes(d,"resource_consuming_operation") or any(x in text for x in ("limit","page","batch","bulk","upload","export","report","search","render","resize","convert","generate","send","email","sms")):
        add_unique(support,{"type":"resource_consuming_operation","source":"endpoint_contract","source_group":"endpoint_contract","weight":16,"text":"Stored endpoint contract exposes a potentially bounded resource-consuming operation."})
    for et in ("resource_limit_missing","resource_limit_weak"):
        if _yes(d,et): add_unique(support,{"type":et,"source":"stored_limit_policy","source_group":"stored_limit_policy","weight":28,"text":f"Stored target policy/evidence records {et.replace('_',' ')}."})
    for et in RESOURCE_BLOCK:
        if _yes(d,et): add_unique(contradict,{"type":et,"source":"stored_limit_policy","source_group":"stored_limit_policy","weight":-44,"text":f"Stored target evidence records {et.replace('_',' ')}."})
    runtime=observations(d,"resource_consumption_observations","rate_limit_observations","pagination_observations","batch_limit_observations")
    for i,obs in enumerate(runtime[:50]):
        g=f"bounded_resource_observation:{i}"
        for et in RESOURCE_BLOCK:
            if truth(scalar(obs,(et,))) is True: add_unique(contradict,{"type":et,"source":"stored_bounded_observation","source_group":g,"weight":-48,"text":f"Bounded stored observation demonstrates {et.replace('_',' ')}."})
        if controlled_observation(obs,bounded=True):
            for et in RESOURCE_DIRECT:
                if truth(scalar(obs,(et,))) is True: add_unique(support,{"type":et,"source":"stored_bounded_observation","source_group":g,"weight":60,"text":f"Bounded authorized observation demonstrates {et.replace('_',' ')}."})
    observed={str(x.get('type') or '') for x in support}; variant=next((x for x in RESOURCE_DIRECT if x in observed),"resource_limit_surface")
    return _result(UnrestrictedResourceConsumptionFamilyAnalyzer(),"unrestricted_resource_consumption",variant,support,contradict,RESOURCE_TAX,({"id":"API4-operation-limit","principle":"Require a concrete resource-consuming operation and stored limit policy/evidence."},{"id":"API4-bounded","principle":"Decisive evidence must be bounded and inside an authorized resource/cost budget."}),("Parameters or missing response headers alone do not prove unrestricted consumption.","No load, concurrency, oversized-body, or cost-amplification test is executed."),({"id":"owasp-api4-2023","source":"OWASP API Security Top 10","ref":"API4:2023","principle":"Bound server/provider resource consumption."},),RESOURCE_DIRECT,("family-api4-operation","family-api4-limit","family-api4-bounded"),"Resource-consumption hypothesis from stored operation/limit evidence; no load test was executed.",20,runtime_observation_count=len(runtime),load_test_performed=False,concurrent_requests_performed=False,cost_amplification_performed=False)

BUSINESS_TAX={"owasp":["API6:2023 Unrestricted Access to Sensitive Business Flows"],"wstg":["WSTG-BUSL-05","WSTG-BUSL-07"],"cwe":["CWE-841"],"capec":[]}
BUSINESS_DIRECT=("business_limit_bypass_observed","excessive_flow_access_accepted")
BUSINESS_BLOCK=("anti_automation_enforced","business_limit_enforced","queue_or_quota_enforced","scarce_inventory_protected")
def analyze_sensitive_business_flow_abuse_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",body_fields:Iterable[str]=(),query_fields:Iterable[str]=(),path_fields:Iterable[str]=(),details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="")->dict[str,Any]|None:
    del db,analysis_id,target,method,body_fields,query_fields,path_fields,business_context; d=dict(details or {}); support=[]; contradict=[]; text=f"{endpoint} {semantic_text}".lower()
    markers=[x for x in ("checkout","purchase","reserve","booking","ticket","signup","register","vote","coupon","redeem","message","invite","claim") if x in text]
    if markers: add_unique(support,{"type":"automation_abuse_surface","source":"endpoint_semantics","source_group":"endpoint_semantics","weight":6,"text":f"Potential automation-sensitive markers: {', '.join(markers[:8])}."})
    if (_yes(d,"sensitive_business_flow") or _yes(d,"business_flow_sensitive")) and bool(d.get("business_abuse_rationale") or d.get("business_sensitivity_reason")):
        add_unique(support,{"type":"sensitive_business_flow","source":"stored_business_policy","source_group":"stored_business_policy","weight":22,"text":"Stored business policy explicitly classifies this flow as sensitive to excessive automated access."})
    for et in ("abuse_control_missing","abuse_control_weak"):
        if _yes(d,et): add_unique(support,{"type":et,"source":"stored_business_policy","source_group":"stored_abuse_control_policy","weight":28,"text":f"Stored business evidence records {et.replace('_',' ')}."})
    for et in BUSINESS_BLOCK:
        if _yes(d,et): add_unique(contradict,{"type":et,"source":"stored_abuse_control_policy","source_group":"stored_abuse_control_policy","weight":-46,"text":f"Stored evidence records {et.replace('_',' ')}."})
    runtime=observations(d,"business_flow_abuse_observations","sensitive_business_flow_observations")
    for i,obs in enumerate(runtime[:40]):
        g=f"reversible_business_flow_observation:{i}"
        for et in BUSINESS_BLOCK:
            if truth(scalar(obs,(et,))) is True: add_unique(contradict,{"type":et,"source":"stored_reversible_observation","source_group":g,"weight":-48,"text":f"Stored controlled observation demonstrates {et.replace('_',' ')}."})
        if controlled_observation(obs,reversible=True) and truth(scalar(obs,("real_inventory_consumed","real_user_impact"))) is not True:
            for et in BUSINESS_DIRECT:
                if truth(scalar(obs,(et,))) is True: add_unique(support,{"type":et,"source":"stored_reversible_observation","source_group":g,"weight":60,"text":f"Reversible test-owned observation demonstrates {et.replace('_',' ')}."})
    observed={str(x.get('type') or '') for x in support}; variant=next((x for x in BUSINESS_DIRECT if x in observed),"sensitive_flow_surface")
    return _result(SensitiveBusinessFlowAbuseFamilyAnalyzer(),"sensitive_business_flow_abuse",variant,support,contradict,BUSINESS_TAX,({"id":"API6-sensitivity","principle":"Require explicit business sensitivity and expected abuse controls."},{"id":"API6-reversible","principle":"Use reversible test-owned observations only."}),("Flow keywords alone do not establish business sensitivity.","Missing CAPTCHA alone is not a vulnerability.","No real transaction or scarce inventory action is automated."),({"id":"owasp-api6-2023","source":"OWASP API Security Top 10","ref":"API6:2023","principle":"Sensitive flows may require restrictions against excessive automated access."},),BUSINESS_DIRECT,("family-api6-sensitivity","family-api6-control","family-api6-reversible"),"Sensitive-business-flow hypothesis from explicit policy and reversible stored evidence.",19,runtime_observation_count=len(runtime),business_action_performed=False,real_inventory_consumed=False,automation_executed=False)

MISCONFIG_TAX={"owasp":["A02:2025 Security Misconfiguration","API8:2023 Security Misconfiguration"],"wstg":["WSTG-CONF"],"cwe":["CWE-16"],"capec":[]}
MISCONFIG_DIRECT=("debug_mode_publicly_exposed","directory_listing_observed","dangerous_http_method_enabled","management_interface_publicly_exposed","insecure_transport_configuration_observed")
MISCONFIG_BLOCK=("secure_configuration_observed","debug_disabled","directory_listing_disabled","dangerous_methods_disabled","management_interface_restricted")
def analyze_security_misconfiguration_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="",**_:Any)->dict[str,Any]|None:
    del db,analysis_id,target,method,business_context; d=dict(details or {}); support=[]; contradict=[]; text=f"{endpoint} {semantic_text}".lower(); direct_present=any(_yes(d,x) for x in MISCONFIG_DIRECT)
    if header_map(d) or direct_present or _yes(d,"configuration_surface") or any(x in text for x in ("debug","admin","management","actuator","swagger","openapi","server-status","directory")):
        add_unique(support,{"type":"configuration_surface","source":"stored_configuration_metadata","source_group":"configuration_surface","weight":14,"text":"A concrete target configuration/deployment surface is present."})
    for et in MISCONFIG_DIRECT:
        if _yes(d,et): add_unique(support,{"type":et,"source":"stored_configuration_observation","source_group":f"configuration_observation:{et}","weight":58,"text":f"Stored target observation demonstrates {et.replace('_',' ')}."})
    for et in MISCONFIG_BLOCK:
        if _yes(d,et): add_unique(contradict,{"type":et,"source":"stored_configuration_observation","source_group":f"configuration_control:{et}","weight":-46,"text":f"Stored target observation demonstrates {et.replace('_',' ')}."})
    runtime=observations(d,"security_misconfiguration_observations","configuration_observations")
    for i,obs in enumerate(runtime[:50]):
        g=f"configuration_observation:{i}"
        for et in MISCONFIG_DIRECT:
            if truth(scalar(obs,(et,))) is True: add_unique(support,{"type":et,"source":"stored_configuration_observation","source_group":g,"weight":58,"text":f"Stored observation demonstrates {et.replace('_',' ')}."})
        for et in MISCONFIG_BLOCK:
            if truth(scalar(obs,(et,))) is True: add_unique(contradict,{"type":et,"source":"stored_configuration_observation","source_group":g,"weight":-46,"text":f"Stored observation demonstrates {et.replace('_',' ')}."})
    observed={str(x.get('type') or '') for x in support}; variant=next((x for x in MISCONFIG_DIRECT if x in observed),"configuration_surface")
    return _result(SecurityMisconfigurationFamilyAnalyzer(),"security_misconfiguration",variant,support,contradict,MISCONFIG_TAX,({"id":"MISCONF-baseline","principle":"Require a concrete target configuration and secure production baseline."},{"id":"MISCONF-deviation","principle":"Promote only observable unsafe deviations."}),("Headers/version strings alone are informational.","Missing optional hardening headers alone are not promoted.","CORS/cache/source-map remain specialized families."),({"id":"owasp-misconfiguration","source":"OWASP","ref":"A02:2025 / API8:2023","principle":"Require a concrete unsafe production configuration."},),MISCONFIG_DIRECT,("family-misconfig-surface","family-misconfig-deviation"),"Security Misconfiguration hypothesis from concrete stored production observations.",18,runtime_observation_count=len(runtime),configuration_change_performed=False,active_request_performed=False)

INVENTORY_TAX={"owasp":["API9:2023 Improper Inventory Management"],"wstg":["WSTG-INFO-04","WSTG-CONF-04"],"cwe":[],"capec":[]}
INVENTORY_DIRECT=("deprecated_api_publicly_reachable","undocumented_api_publicly_reachable","debug_api_publicly_reachable","stale_api_host_publicly_reachable")
INVENTORY_BLOCK=("inventory_documented","version_decommissioned","debug_endpoint_restricted","stale_host_not_reachable")
def analyze_improper_inventory_management_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="",**_:Any)->dict[str,Any]|None:
    del db,analysis_id,target,method,business_context; d=dict(details or {}); support=[]; contradict=[]; text=f"{endpoint} {semantic_text}".lower(); direct_present=any(_yes(d,x) for x in INVENTORY_DIRECT)
    surface=_yes(d,"api_inventory_surface") or direct_present or bool(re.search(r"/(?:api/)?v\d+(?:/|$)",text)) or any(x in text for x in ("/debug","/swagger","/openapi","/graphql","/actuator"))
    if surface: add_unique(support,{"type":"api_inventory_surface","source":"observed_api_surface","source_group":"observed_api_surface","weight":16,"text":"A concrete API version/host/debug/documentation surface is present."})
    if _yes(d,"inventory_drift_signal") and bool(d.get("inventory_baseline") or d.get("lifecycle_status")): add_unique(support,{"type":"inventory_drift_signal","source":"authoritative_inventory_comparison","source_group":"authoritative_inventory_comparison","weight":30,"text":"Stored comparison against authoritative inventory/lifecycle data indicates drift."})
    for et in INVENTORY_DIRECT:
        if _yes(d,et): add_unique(support,{"type":et,"source":"stored_inventory_observation","source_group":f"inventory_reachability:{et}","weight":60,"text":f"Stored target evidence demonstrates {et.replace('_',' ')}."})
    for et in INVENTORY_BLOCK:
        if _yes(d,et): add_unique(contradict,{"type":et,"source":"stored_inventory_control","source_group":"authoritative_inventory_comparison","weight":-46,"text":f"Stored lifecycle evidence records {et.replace('_',' ')}."})
    runtime=observations(d,"api_inventory_observations","inventory_management_observations")
    for i,obs in enumerate(runtime[:50]):
        g=f"inventory_observation:{i}"
        for et in INVENTORY_DIRECT:
            if truth(scalar(obs,(et,))) is True: add_unique(support,{"type":et,"source":"stored_inventory_observation","source_group":g,"weight":60,"text":f"Stored target observation demonstrates {et.replace('_',' ')}."})
        for et in INVENTORY_BLOCK:
            if truth(scalar(obs,(et,))) is True: add_unique(contradict,{"type":et,"source":"stored_inventory_observation","source_group":g,"weight":-46,"text":f"Stored observation demonstrates {et.replace('_',' ')}."})
    observed={str(x.get('type') or '') for x in support}; variant=next((x for x in INVENTORY_DIRECT if x in observed),"inventory_drift" if "inventory_drift_signal" in observed else "api_inventory_surface")
    return _result(ImproperInventoryManagementFamilyAnalyzer(),"improper_inventory_management",variant,support,contradict,INVENTORY_TAX,({"id":"API9-surface","principle":"Record concrete API versions/hosts/debug surfaces."},{"id":"API9-baseline","principle":"Compare with authoritative inventory and lifecycle data."}),("Versioned paths are normal and not drift by themselves.","Undocumented routes need an authoritative baseline.","No scope expansion is performed."),({"id":"owasp-api9-2023","source":"OWASP API Security Top 10","ref":"API9:2023","principle":"Maintain an accurate API inventory and lifecycle."},),INVENTORY_DIRECT,("family-api9-surface","family-api9-drift","family-api9-reachability"),"API inventory hypothesis from observed surfaces and stored lifecycle comparison.",16,runtime_observation_count=len(runtime),scope_expansion_performed=False,active_request_performed=False)

UPSTREAM_TAX={"owasp":["API10:2023 Unsafe Consumption of APIs"],"wstg":["WSTG-APIT"],"cwe":["CWE-20","CWE-319","CWE-400"],"capec":[]}
UPSTREAM_DIRECT=("untrusted_upstream_data_reaches_sensitive_sink","unencrypted_upstream_observed","cross_trust_upstream_redirect_followed","upstream_response_limit_bypass_observed")
UPSTREAM_BLOCK=("upstream_validation_enforced","upstream_tls_enforced","upstream_timeout_enforced","upstream_size_limit_enforced","upstream_redirect_policy_enforced")
def analyze_unsafe_api_consumption_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",body_fields:Iterable[str]=(),query_fields:Iterable[str]=(),path_fields:Iterable[str]=(),details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="")->dict[str,Any]|None:
    del db,analysis_id,target,method,path_fields,business_context; d=dict(details or {}); support=[]; contradict=[]; text=f"{endpoint} {semantic_text} {' '.join(map(str,[*body_fields,*query_fields]))}".lower()
    if _yes(d,"third_party_api_integration") or bool(d.get("upstream_service") or d.get("third_party_service")) or any(x in text for x in ("third-party","third_party","partner api","vendor api","external api")): add_unique(support,{"type":"third_party_api_integration","source":"integration_contract","source_group":"integration_contract","weight":18,"text":"Stored context identifies a third-party/upstream API integration."})
    if _yes(d,"upstream_data_trust_boundary") or bool(d.get("upstream_response_consumer") or d.get("downstream_sink")): add_unique(support,{"type":"upstream_data_trust_boundary","source":"dataflow_contract","source_group":"upstream_dataflow_contract","weight":20,"text":"Stored context identifies an upstream-response trust boundary into downstream processing."})
    for et in ("upstream_validation_missing","upstream_tls_missing","upstream_timeout_missing","upstream_size_limit_missing","upstream_redirect_unrestricted"):
        if _yes(d,et): add_unique(support,{"type":et,"source":"stored_upstream_policy","source_group":"stored_upstream_policy","weight":28,"text":f"Stored target-side evidence records {et.replace('_',' ')}."})
    for et in UPSTREAM_BLOCK:
        if _yes(d,et): add_unique(contradict,{"type":et,"source":"stored_upstream_policy","source_group":"stored_upstream_policy","weight":-46,"text":f"Stored target-side evidence records {et.replace('_',' ')}."})
    runtime=observations(d,"unsafe_api_consumption_observations","upstream_api_observations","third_party_api_observations")
    for i,obs in enumerate(runtime[:50]):
        g=f"target_side_upstream_observation:{i}"
        for et in UPSTREAM_BLOCK:
            if truth(scalar(obs,(et,))) is True: add_unique(contradict,{"type":et,"source":"stored_target_side_observation","source_group":g,"weight":-48,"text":f"Stored target-side observation demonstrates {et.replace('_',' ')}."})
        if controlled_observation(obs) and truth(scalar(obs,("third_party_probe_performed","upstream_attack_performed"))) is not True:
            for et in UPSTREAM_DIRECT:
                if truth(scalar(obs,(et,))) is True: add_unique(support,{"type":et,"source":"stored_target_side_observation","source_group":g,"weight":60,"text":f"Authorized target-side observation demonstrates {et.replace('_',' ')}."})
    observed={str(x.get('type') or '') for x in support}; variant=next((x for x in UPSTREAM_DIRECT if x in observed),"upstream_trust_boundary")
    return _result(UnsafeApiConsumptionFamilyAnalyzer(),"unsafe_api_consumption",variant,support,contradict,UPSTREAM_TAX,({"id":"API10-boundary","principle":"Identify the third-party dependency and downstream trust boundary."},{"id":"API10-target-side","principle":"Use target-side evidence only; never attack the upstream service."}),("Third-party integration alone is normal.","Missing control evidence is not evidence the control is absent.","No upstream service is probed."),({"id":"owasp-api10-2023","source":"OWASP API Security Top 10","ref":"API10:2023","principle":"Treat integrated API data as untrusted and bound transport/validation/redirect/timeout/size."},),UPSTREAM_DIRECT,("family-api10-integration","family-api10-boundary","family-api10-target-side"),"Unsafe API Consumption hypothesis from stored target-side upstream trust controls.",20,runtime_observation_count=len(runtime),third_party_probe_performed=False,upstream_attack_performed=False,active_request_performed=False)

class UnrestrictedResourceConsumptionFamilyAnalyzer(FamilyAnalyzer):
    family="unrestricted_resource_consumption"; analyzer_version="1.0.0"
    def analyze(self,c:FamilyAnalyzerContext,**kw): return analyze_unrestricted_resource_consumption_signal(c.db,analysis_id=c.analysis_id,target=c.target,endpoint=c.endpoint,method=c.method,details=c.details,business_context=c.business_context,**kw)
class SensitiveBusinessFlowAbuseFamilyAnalyzer(FamilyAnalyzer):
    family="sensitive_business_flow_abuse"; analyzer_version="1.0.0"
    def analyze(self,c:FamilyAnalyzerContext,**kw): return analyze_sensitive_business_flow_abuse_signal(c.db,analysis_id=c.analysis_id,target=c.target,endpoint=c.endpoint,method=c.method,details=c.details,business_context=c.business_context,**kw)
class SecurityMisconfigurationFamilyAnalyzer(FamilyAnalyzer):
    family="security_misconfiguration"; analyzer_version="1.0.0"
    def analyze(self,c:FamilyAnalyzerContext,**kw): return analyze_security_misconfiguration_signal(c.db,analysis_id=c.analysis_id,target=c.target,endpoint=c.endpoint,method=c.method,details=c.details,business_context=c.business_context,**kw)
class ImproperInventoryManagementFamilyAnalyzer(FamilyAnalyzer):
    family="improper_inventory_management"; analyzer_version="1.0.0"
    def analyze(self,c:FamilyAnalyzerContext,**kw): return analyze_improper_inventory_management_signal(c.db,analysis_id=c.analysis_id,target=c.target,endpoint=c.endpoint,method=c.method,details=c.details,business_context=c.business_context,**kw)
class UnsafeApiConsumptionFamilyAnalyzer(FamilyAnalyzer):
    family="unsafe_api_consumption"; analyzer_version="1.0.0"
    def analyze(self,c:FamilyAnalyzerContext,**kw): return analyze_unsafe_api_consumption_signal(c.db,analysis_id=c.analysis_id,target=c.target,endpoint=c.endpoint,method=c.method,details=c.details,business_context=c.business_context,**kw)
