from __future__ import annotations
from typing import Any, Iterable, Mapping
from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .owasp_expansion_common import analyze_injection_family

COMMAND_INJECTION_FAMILY_ANALYZER_VERSION = "1.0.0"
TAXONOMY = {'owasp': ['Injection'], 'wstg': ['WSTG-INPV-12'], 'cwe': ['CWE-78'], 'capec': ['CAPEC-88']}
METHOD = (
    {"id":"command_injection-input-sink","principle":"Require concrete user input plus a matching server-side interpreter/query sink."},
    {"id":"command_injection-safe-controls","principle":"Treat parameterization/escaping/typing/literal rendering/allow-listing as contradiction evidence."},
    {"id":"command_injection-controlled","principle":"Only authorized benign stored observations may be decisive."},
)
FALSE_POSITIVES = (
    "Parameter or endpoint keywords alone are discovery context, not injection evidence.",
    "A sink keyword alone does not prove untrusted data reaches the sink.",
    "OWASP/CWE/write-up knowledge never counts as target evidence.",
)
WRITEUPS = ({"id":"owasp-command_injection","source":"OWASP","ref":'WSTG-INPV-12',"principle":"Untrusted input becomes dangerous only when it can alter interpreter semantics at a server-side sink."},)

def analyze_command_injection_signal(db:Database,*,analysis_id:str,target:str,endpoint:str="",method:str="UNKNOWN",body_fields:Iterable[str]=(),query_fields:Iterable[str]=(),path_fields:Iterable[str]=(),details:Mapping[str,Any]|None=None,business_context:str="general",semantic_text:str="")->dict[str,Any]|None:
    del db,analysis_id,target,business_context
    return analyze_injection_family(analyzer=CommandInjectionFamilyAnalyzer(),family='command_injection',variant='os_command_construction',endpoint=endpoint,method=method,body_fields=body_fields,query_fields=query_fields,path_fields=path_fields,details=details,semantic_text=semantic_text,input_type='command_input',sink_type='os_command_sink',input_keywords=('host', 'hostname', 'ip', 'file', 'path', 'target', 'command', 'cmd', 'argument', 'args', 'url'),sink_keywords=('subprocess', 'os.system', 'popen', 'shell', 'cmd.exe', 'powershell', 'runtime.exec', 'processbuilder', 'child_process'),unsafe_types=('unsafe_command_construction_observed',),direct_types=('command_execution_influence_observed', 'command_argument_boundary_bypass_observed'),contradiction_types=('argument_array_enforced', 'command_allowlist_enforced', 'input_not_reaching_command'),observation_keys=('command_injection_observations', 'process_execution_observations', 'command_runtime_observations'),taxonomy=TAXONOMY,methodology=METHOD,false_positive_checks=FALSE_POSITIVES,writeup_patterns=WRITEUPS,rule_ids=("family-command_injection-input","family-command_injection-sink","family-command_injection-controlled-behavior"),summary='OS Command Injection'+" hypothesis from stored target evidence; no payload was generated or sent.",base=26)

class CommandInjectionFamilyAnalyzer(FamilyAnalyzer):
    family='command_injection'; analyzer_version=COMMAND_INJECTION_FAMILY_ANALYZER_VERSION
    def analyze(self,context:FamilyAnalyzerContext,**kwargs:Any)->dict[str,Any]|None:
        return analyze_command_injection_signal(context.db,analysis_id=context.analysis_id,target=context.target,endpoint=context.endpoint,method=context.method,details=context.details,business_context=context.business_context,**kwargs)
