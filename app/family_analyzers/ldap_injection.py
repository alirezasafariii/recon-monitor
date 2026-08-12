from __future__ import annotations
from typing import Any, Iterable, Mapping
from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .owasp_expansion_common import analyze_injection_family

LDAP_INJECTION_FAMILY_ANALYZER_VERSION = "1.0.0"
TAXONOMY = {'owasp': ['Injection'], 'wstg': ['WSTG-INPV-06'], 'cwe': ['CWE-90'], 'capec': []}
METHOD = (
    {"id":"ldap_injection-input-sink","principle":"Require concrete user input plus a matching server-side interpreter/query sink."},
    {"id":"ldap_injection-safe-controls","principle":"Treat parameterization/escaping/typing/literal rendering/allow-listing as contradiction evidence."},
    {"id":"ldap_injection-controlled","principle":"Only authorized benign stored observations may be decisive."},
)
FALSE_POSITIVES = (
    "Parameter or endpoint keywords alone are discovery context, not injection evidence.",
    "A sink keyword alone does not prove untrusted data reaches the sink.",
    "OWASP/CWE/write-up knowledge never counts as target evidence.",
)
WRITEUPS = ({"id":"owasp-ldap_injection","source":"OWASP","ref":'WSTG-INPV-06',"principle":"Untrusted input becomes dangerous only when it can alter interpreter semantics at a server-side sink."},)

def analyze_ldap_injection_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",body_fields:Iterable[str]=(),query_fields:Iterable[str]=(),path_fields:Iterable[str]=(),details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="")->dict[str,Any]|None:
    del db,analysis_id,target,business_context
    return analyze_injection_family(analyzer=LdapInjectionFamilyAnalyzer(),family='ldap_injection',variant='ldap_filter_construction',endpoint=endpoint,method=method,body_fields=body_fields,query_fields=query_fields,path_fields=path_fields,details=details,semantic_text=semantic_text,input_type='ldap_input',sink_type='ldap_filter_sink',input_keywords=('user', 'username', 'uid', 'cn', 'dn', 'filter', 'search', 'group', 'mail', 'email'),sink_keywords=('ldap', 'directory search', 'search filter', 'distinguished name', 'bind dn', 'ldapsearch'),unsafe_types=('unsafe_ldap_filter_construction_observed',),direct_types=('ldap_filter_influence_observed', 'ldap_query_differential'),contradiction_types=('ldap_filter_escaping_observed', 'ldap_parameterization_observed', 'input_not_reaching_ldap'),observation_keys=('ldap_injection_observations', 'ldap_query_observations', 'ldap_runtime_observations'),taxonomy=TAXONOMY,methodology=METHOD,false_positive_checks=FALSE_POSITIVES,writeup_patterns=WRITEUPS,rule_ids=("family-ldap_injection-input","family-ldap_injection-sink","family-ldap_injection-controlled-behavior"),summary='LDAP Injection'+" hypothesis from stored target evidence; no payload was generated or sent.",base=22)

class LdapInjectionFamilyAnalyzer(FamilyAnalyzer):
    family='ldap_injection'; analyzer_version=LDAP_INJECTION_FAMILY_ANALYZER_VERSION
    def analyze(self,context:FamilyAnalyzerContext,**kwargs:Any)->dict[str,Any]|None:
        return analyze_ldap_injection_signal(context.db,analysis_id=context.analysis_id,target=context.target,endpoint=context.endpoint,method=context.method,details=context.details,business_context=context.business_context,**kwargs)
