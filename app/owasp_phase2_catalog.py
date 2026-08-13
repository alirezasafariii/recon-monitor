from __future__ import annotations
"""Canonical data-only catalog for Analysis expansion phase 2. No probes or target I/O."""
from owasp_phase2_catalog_part1 import ROWS as _R1
from owasp_phase2_catalog_part2 import ROWS as _R2
from owasp_phase2_catalog_part3 import ROWS as _R3
def _s(v): return [x for x in v.split(";") if x]
ROWS=[*_R1,*_R2,*_R3]
PHASE2_FAMILY_SPECS={}
for r in ROWS:
    family,label,impact,category,validation,owasp,wstg,cwe,capec,context,unsafe,direct,contradictions,keywords=r
    PHASE2_FAMILY_SPECS[family]={"label":label,"impact":impact,"category":category,"validation":validation,"owasp":_s(owasp),"wstg":_s(wstg),"cwe":_s(cwe),"capec":_s(capec),"context":_s(context),"unsafe":_s(unsafe),"direct":_s(direct),"contradictions":_s(contradictions),"keywords":_s(keywords),"safe":"Use only stored target observations and explicitly authorized benign controlled validation. Do not generate exploit payloads, perform destructive/state-changing actions, access third-party data, or turn taxonomy/write-up material into target evidence."}
PHASE2_FAMILY_ORDER=tuple(PHASE2_FAMILY_SPECS)
PHASE2_TAXONOMY={f:{k:list(s[k]) for k in ("owasp","wstg","cwe","capec")} for f,s in PHASE2_FAMILY_SPECS.items()}
PHASE2_BUG_FAMILY_METADATA={f:{"label":s["label"],"impact":s["impact"],"category":s["category"]} for f,s in PHASE2_FAMILY_SPECS.items()}
PHASE2_SAFE_ACTIONS={f:s["safe"] for f,s in PHASE2_FAMILY_SPECS.items()}
PHASE2_DIRECT_TYPES={f:tuple(s["direct"]) for f,s in PHASE2_FAMILY_SPECS.items()}
assert len(PHASE2_FAMILY_ORDER)==43 and len(set(PHASE2_FAMILY_ORDER))==43
