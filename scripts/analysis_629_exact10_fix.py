from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    target = Path(path)
    text = target.read_text(encoding='utf-8')
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected exactly one match, found {count}')
    target.write_text(text.replace(old, new), encoding='utf-8')


old = '''        "sensitive_business_flow_abuse", "source_map_exposure",\n        "unsafe_api_consumption", "websocket_authorization",'''
new = '''        "sensitive_business_flow_abuse", "software_supply_chain_failure",\n        "source_map_exposure", "unsafe_api_consumption", "websocket_authorization",'''

replace_once(
    'app/raw_recon_v5_nvd_discovery.py',
    old,
    new,
    'allow software supply chain exact supplement in NVD discovery',
)
replace_once(
    'app/raw_recon_v5_prepare.py',
    old,
    new,
    'require software supply chain exact supplement in prepare',
)

print('v5 exact supplement family contract expanded from 9 to 10')
