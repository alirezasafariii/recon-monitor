from __future__ import annotations

from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def build_evaluator() -> None:
    src=(ROOT/'app/v6_benchmark_evaluate.py').read_text(encoding='utf-8')
    replacements=(
        ('from v6_benchmark_validate import validate_v6_corpus','from v7_benchmark_validate import validate_v7_corpus'),
        ('from v6_freeze_verify import verify_freeze','from v7_freeze_verify import verify_freeze'),
        ('validate_v6_corpus(', 'validate_v7_corpus('),
        ('analysis_raw_v6.jsonl','analysis_raw_v7.jsonl'),
        ('v6_shortlist.json','v7_shortlist.json'),
        ('v6_protocol.json','v7_protocol.json'),
        ('v6_corpus_freeze.json','v7_corpus_freeze.json'),
        ('v6_evaluator_freeze.json','v7_evaluator_freeze.json'),
        ('v6_first_blind_consumption.json','v7_first_blind_consumption.json'),
        ('analysis_raw_v6_first_blind.json','analysis_raw_v7_first_blind.json'),
        ('run_v6_benchmark','run_v7_benchmark'),
        ('fresh_blind_v6','fresh_blind_v7'),
        ('V6 ', 'V7 '),
        ('v6 ', 'v7 '),
        ('VERSION = "1.2.0"','VERSION = "1.0.0"'),
        ('RULE_VERSION = "2026.08.14.6.31.16"','RULE_VERSION = "2026.08.14.6.32.v7.19"'),
    )
    for old,new in replacements:
        src=src.replace(old,new)
    if 'analysis_raw_v6.jsonl' in src or 'v6_first_blind_consumption.json' in src or 'run_v6_benchmark' in src:
        raise RuntimeError('v7 evaluator still contains canonical v6 execution path')
    if 'validate_v6_corpus' in src or 'v6_freeze_verify' in src:
        raise RuntimeError('v7 evaluator still imports v6 validation/freeze')
    (ROOT/'app/v7_benchmark_evaluate.py').write_text(src,encoding='utf-8')


def build_consumer() -> None:
    src=(ROOT/'app/v6_first_blind_consume.py').read_text(encoding='utf-8')
    replacements=(
        ('from v6_benchmark_evaluate import run_v6_benchmark','from v7_benchmark_evaluate import run_v7_benchmark'),
        ('from v6_freeze_verify import verify_freeze','from v7_freeze_verify import verify_freeze'),
        ('run_v6_benchmark()', 'run_v7_benchmark()'),
        ('analysis_raw_v6.jsonl','analysis_raw_v7.jsonl'),
        ('v6_shortlist.json','v7_shortlist.json'),
        ('v6_protocol.json','v7_protocol.json'),
        ('v6_corpus_freeze.json','v7_corpus_freeze.json'),
        ('v6_evaluator_freeze.json','v7_evaluator_freeze.json'),
        ('v6_benchmark_evaluate.py','v7_benchmark_evaluate.py'),
        ('v6_first_blind_consumption.json','v7_first_blind_consumption.json'),
        ('analysis_raw_v6_first_blind.json','analysis_raw_v7_first_blind.json'),
        ('fresh_blind_v6','fresh_blind_v7'),
        ('Analysis 6.31','Analysis 6.32 v7'),
        ('VERSION = "1.0.0"','VERSION = "1.0.0"'),
        ('RULE_VERSION = "2026.08.14.6.31.15"','RULE_VERSION = "2026.08.14.6.32.v7.20"'),
    )
    for old,new in replacements:
        src=src.replace(old,new)
    if 'analysis_raw_v6.jsonl' in src or 'v6_first_blind_consumption.json' in src or 'run_v6_benchmark' in src:
        raise RuntimeError('v7 consumption wrapper still contains v6 canonical execution path')
    if 'v6_freeze_verify' in src or 'v6_benchmark_evaluate' in src:
        raise RuntimeError('v7 consumption wrapper still imports v6 scoring surface')
    (ROOT/'app/v7_first_blind_consume.py').write_text(src,encoding='utf-8')


def main() -> None:
    build_evaluator();build_consumer();print('built preregistered v7 evaluator and one-time consumption wrapper')

if __name__=='__main__':main()
