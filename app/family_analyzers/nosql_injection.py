from __future__ import annotations
from typing import Any, Iterable, Mapping
from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .owasp_expansion_common import analyze_injection_family

NOSQL_INJECTION_FAMILY_ANALYZER_VERSION = "1.0.0"
TAXONOMY = {'owasp': ['Injection'], 'wstg': ['WSTG-INPV-05.6'], 'cwe': ['CWE-943'], 'capec': []}
METHOD = (
    {"id":"nosql_injection-input-sink","principle":"Require concrete user input plus a matching server-side interpreter/query sink."},
    {"id":"nosql_injection-safe-controls","principle":"Treat parameterization/escaping/typing/literal rendering/allow-listing as contradiction evidence."},
    {"id":"nosql_injection-controlled","principle":"Only authorized benign stored observations may be decisive."},
)
FALSE_POSITIVES = (
    "Parameter or endpoint keywords alone are discovery context, not injection evidence.",
    "A sink keyword alone does not prove untrusted data reaches the sink.",
    "OWASP/CWE/write-up knowledge never counts as target evidence.",
)
WRITEUPS = ({"id":"owasp-nosql_injection","source":"OWASP","ref":'WSTG-INPV-05.6',"principle":"Untrusted input becomes dangerous only when it can alter interpreter semantics at a server-side sink."},)

def analyze_nosql_injection_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",body_fields:Iterable[str]=(),query_fields:Iterable[str]=(),path_fields:Iterable[str]=(),details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="")->dict[str,Any]|None:
    del db,analysis_id,target,business_context
    return analyze_injection_family(analyzer=NoSqlInjectionFamilyAnalyzer(),family='nosql_injection',variant='nosql_query_construction',endpoint=endpoint,method=method,body_fields=body_fields,query_fields=query_fields,path_fields=path_fields,details=details,semantic_text=semantic_text,input_type='nosql_input',sink_type='nosql_query_sink',input_keywords=('filter', 'query', 'where', 'selector', 'search', 'match', 'pipeline', 'conditions'),sink_keywords=('mongodb', 'mongo', 'find(', 'findone', 'aggregate', 'bson', 'documentdb', 'nosql', 'query object'),unsafe_types=('unsafe_nosql_query_construction_observed', 'nosql_operator_surface_observed'),direct_types=('nosql_query_influence_observed', 'nosql_operator_injection_observed'),contradiction_types=('typed_schema_enforced', 'nosql_operator_allowlist_enforced', 'input_not_reaching_query'),observation_keys=('nosql_injection_observations', 'nosql_query_observations', 'nosql_runtime_observations'),taxonomy=TAXONOMY,methodology=METHOD,false_positive_checks=FALSE_POSITIVES,writeup_patterns=WRITEUPS,rule_ids=("family-nosql_injection-input","family-nosql_injection-sink","family-nosql_injection-controlled-behavior"),summary='NoSQL Injection'+" hypothesis from stored target evidence; no payload was generated or sent.",base=23)

class NoSqlInjectionFamilyAnalyzer(FamilyAnalyzer):
    family='nosql_injection'; analyzer_version=NOSQL_INJECTION_FAMILY_ANALYZER_VERSION
    def analyze(self,context:FamilyAnalyzerContext,**kwargs:Any)->dict[str,Any]|None:
        return analyze_nosql_injection_signal(context.db,analysis_id=context.analysis_id,target=context.target,endpoint=context.endpoint,method=context.method,details=context.details,business_context=context.business_context,**kwargs)
