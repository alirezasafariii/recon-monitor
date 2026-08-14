from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "app/analysis_632_evidence.py"
text = PATH.read_text(encoding="utf-8")

old = '''        "analysis_632_basis": "explicit_stored_fact_semantic_reconstruction",
    }
'''
new = '''        "analysis_632_basis": "explicit_stored_fact_semantic_reconstruction",
        "execution_engine_version": "1.4.0",
        "execution_rule_version": "2026.08.13.6.30",
        "execution_family": family,
        "execution_strategy": "analysis_632_stored_assertion_bridge",
        "execution_basis": "passive_stored_assertion",
        "execution_passive_only": True,
    }
'''
if old not in text:
    raise RuntimeError("metadata refinement anchor missing")
text = text.replace(old, new, 1)

old = '''        # Identity reconstruction is allowed from the combined stored context,
        # but still requires a semantic match to the canonical identity signal.
        for signal in sorted(identity_signals):
            if _semantic_match(signal, context_text, condition=False) >= 0.67:
                _emit(packet, family, signal, f"Stored context supports family identity signal: {signal}.", role="identity", path="stored_context")

        # Conditions and controls must come from an explicit fact. A generic
'''
new = '''        # Analysis 6.32 intentionally does not infer family identity from broad
        # narrative context. Existing physical detectors own surface identity.
        # Only an explicit stored boolean/key matching a canonical identity
        # signal may add identity evidence here.
        for path, value in facts:
            leaf = _norm(path.split(".")[-1])
            if not _truthy(value):
                continue
            for signal in sorted(identity_signals):
                if leaf == _norm(signal):
                    _emit(packet, family, signal, f"Stored fact explicitly asserts family identity signal {signal}.", role="identity", path=path)

        # Conditions and controls must come from an explicit fact. A generic
'''
if old not in text:
    raise RuntimeError("identity refinement anchor missing")
text = text.replace(old, new, 1)

old = '''                explicit_boolean = _truthy(value) and key_match >= 0.60
                if explicit_boolean or text_match >= 0.72 or _phrase_hit(signal, text):
'''
new = '''                leaf = _norm(path.split(".")[-1])
                explicit_boolean = _truthy(value) and (leaf == _norm(signal) or key_match >= 0.90)
                if explicit_boolean or text_match >= 0.82 or _phrase_hit(signal, text):
'''
if old not in text:
    raise RuntimeError("condition precision anchor missing")
text = text.replace(old, new, 1)

old = '''            for signal in sorted(control_signals):
                key_match = _semantic_match(signal, path.replace("_", " "), condition=False)
                text_match = _semantic_match(signal, text, condition=False)
                if (_truthy(value) and key_match >= 0.60) or (_looks_secure_control(text) and text_match >= 0.65):
                    _emit(packet, family, signal, f"Stored fact supports blocking control {signal}: {text}", role="control", path=path)
'''
new = '''            for signal in sorted(control_signals):
                leaf = _norm(path.split(".")[-1])
                text_match = _semantic_match(signal, text, condition=False)
                explicit_control = _truthy(value) and leaf == _norm(signal)
                # A false-valued control flag (for example signature_verified=false)
                # is evidence that the control is absent, never proof that it exists.
                secure_narrative = (not _falsey(value)) and _looks_secure_control(text) and text_match >= 0.95
                if explicit_control or secure_narrative:
                    _emit(packet, family, signal, f"Stored fact supports blocking control {signal}: {text}", role="control", path=path)
'''
if old not in text:
    raise RuntimeError("control precision anchor missing")
text = text.replace(old, new, 1)

PATH.write_text(text, encoding="utf-8")
print("Analysis 6.32 evidence reconstruction precision tightened")
