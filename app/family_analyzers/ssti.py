from __future__ import annotations
from typing import Any, Iterable, Mapping
from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .owasp_expansion_common import analyze_injection_family

SSTI_FAMILY_ANALYZER_VERSION = "1.0.0"
TAXONOMY = {'owasp': ['Injection'], 'wstg': ['WSTG-INPV-18'], 'cwe': ['CWE-1336'], 'capec': []}
METHOD = (
    {"id":"ssti-input-sink","principle":"Require concrete user input plus a matching server-side interpreter/query sink."},
    {"id":"ssti-safe-controls","principle":"Treat parameterization/escaping/typing/literal rendering/allow-listing as contradiction evidence."},
    {"id":"ssti-controlled","principle":"Only authorized benign stored observations may be decisive."},
)
FALSE_POSITIVES = (
    "Parameter or endpoint keywords alone are discovery context, not injection evidence.",
    "A sink keyword alone does not prove untrusted data reaches the sink.",
    "OWASP/CWE/write-up knowledge never counts as target evidence.",
)
WRITEUPS = ({"id":"owasp-ssti","source":"OWASP","ref":'WSTG-INPV-18',"principle":"Untrusted input becomes dangerous only when it can alter interpreter semantics at a server-side sink."},)

def analyze_ssti_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",body_fields:Iterable[str]=(),query_fields:Iterable[str]=(),path_fields:Iterable[str]=(),details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="")->dict[str,Any]|None:
    del db,analysis_id,target,business_context
    return analyze_injection_family(analyzer=SstiFamilyAnalyzer(),family='ssti',variant='server_template_rendering',endpoint=endpoint,method=method,body_fields=body_fields,query_fields=query_fields,path_fields=path_fields,details=details,semantic_text=semantic_text,input_type='template_input',sink_type='server_template_sink',input_keywords=('template', 'content', 'body', 'message', 'subject', 'name', 'format', 'view'),sink_keywords=('render_template', 'render string', 'template engine', 'jinja', 'twig', 'freemarker', 'velocity', 'mustache', 'handlebars', 'thymeleaf'),unsafe_types=('unsafe_template_interpolation_observed',),direct_types=('template_expression_evaluated', 'template_sandbox_escape_observed'),contradiction_types=('literal_template_rendering_observed', 'template_sandbox_enforced', 'input_not_reaching_template'),observation_keys=('ssti_observations', 'template_runtime_observations', 'server_template_observations'),taxonomy=TAXONOMY,methodology=METHOD,false_positive_checks=FALSE_POSITIVES,writeup_patterns=WRITEUPS,rule_ids=("family-ssti-input","family-ssti-sink","family-ssti-controlled-behavior"),summary='Server-Side Template Injection'+" hypothesis from stored target evidence; no payload was generated or sent.",base=25)

class SstiFamilyAnalyzer(FamilyAnalyzer):
    family='ssti'; analyzer_version=SSTI_FAMILY_ANALYZER_VERSION
    def analyze(self,context:FamilyAnalyzerContext,**kwargs:Any)->dict[str,Any]|None:
        return analyze_ssti_signal(context.db,analysis_id=context.analysis_id,target=context.target,endpoint=context.endpoint,method=context.method,details=context.details,business_context=context.business_context,**kwargs)
