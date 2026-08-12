from __future__ import annotations
from typing import Any, Iterable, Mapping
from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .owasp_expansion_common import analyze_injection_family

SQL_INJECTION_FAMILY_ANALYZER_VERSION = "1.0.0"
TAXONOMY = {'owasp': ['Injection'], 'wstg': ['WSTG-INPV-05'], 'cwe': ['CWE-89'], 'capec': ['CAPEC-66']}
METHOD = (
    {"id":"sql_injection-input-sink","principle":"Require concrete user input plus a matching server-side interpreter/query sink."},
    {"id":"sql_injection-safe-controls","principle":"Treat parameterization/escaping/typing/literal rendering/allow-listing as contradiction evidence."},
    {"id":"sql_injection-controlled","principle":"Only authorized benign stored observations may be decisive."},
)
FALSE_POSITIVES = (
    "Parameter or endpoint keywords alone are discovery context, not injection evidence.",
    "A sink keyword alone does not prove untrusted data reaches the sink.",
    "OWASP/CWE/write-up knowledge never counts as target evidence.",
)
WRITEUPS = ({"id":"owasp-sql_injection","source":"OWASP","ref":'WSTG-INPV-05',"principle":"Untrusted input becomes dangerous only when it can alter interpreter semantics at a server-side sink."},)

def analyze_sql_injection_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",body_fields:Iterable[str]=(),query_fields:Iterable[str]=(),path_fields:Iterable[str]=(),details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="")->dict[str,Any]|None:
    del db,analysis_id,target,business_context
    return analyze_injection_family(analyzer=SqlInjectionFamilyAnalyzer(),family='sql_injection',variant='sql_query_construction',endpoint=endpoint,method=method,body_fields=body_fields,query_fields=query_fields,path_fields=path_fields,details=details,semantic_text=semantic_text,input_type='sql_input',sink_type='sql_query_sink',input_keywords=('id', 'query', 'search', 'filter', 'sort', 'order', 'where', 'name', 'email', 'username'),sink_keywords=('select ', 'insert ', 'update ', 'delete ', 'execute ', 'sql', 'database', 'cursor', 'query('),unsafe_types=('unsafe_sql_concatenation_observed', 'sql_error_signature_observed'),direct_types=('sql_query_influence_observed', 'sql_behavior_differential'),contradiction_types=('parameterized_query_observed', 'query_parameter_binding_observed', 'input_not_reaching_query'),observation_keys=('sql_injection_observations', 'database_query_observations', 'sql_runtime_observations'),taxonomy=TAXONOMY,methodology=METHOD,false_positive_checks=FALSE_POSITIVES,writeup_patterns=WRITEUPS,rule_ids=("family-sql_injection-input","family-sql_injection-sink","family-sql_injection-controlled-behavior"),summary='SQL Injection'+" hypothesis from stored target evidence; no payload was generated or sent.",base=24)

class SqlInjectionFamilyAnalyzer(FamilyAnalyzer):
    family='sql_injection'; analyzer_version=SQL_INJECTION_FAMILY_ANALYZER_VERSION
    def analyze(self,context:FamilyAnalyzerContext,**kwargs:Any)->dict[str,Any]|None:
        return analyze_sql_injection_signal(context.db,analysis_id=context.analysis_id,target=context.target,endpoint=context.endpoint,method=context.method,details=context.details,business_context=context.business_context,**kwargs)
