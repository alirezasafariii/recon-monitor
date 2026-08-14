from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

replacements={
 'app/raw_recon_v7_patch_probe.py':[
  ("if not files or not patch_text or not added or not removed:\n                rejected[\"patch_not_bidirectional\"] = rejected.get(\"patch_not_bidirectional\", 0) + 1\n                continue",
   "if not files or not patch_text or not added:\n                rejected[\"patch_has_no_added_fix\"] = rejected.get(\"patch_has_no_added_fix\", 0) + 1\n                continue"),
 ],
 'app/raw_recon_v7_preferred_patch_probe.py':[
  ("if not files or not added or not removed or not patch_text:reasons.append('patch_not_bidirectional');continue",
   "if not files or not added or not patch_text:reasons.append('patch_has_no_added_fix');continue"),
 ],
 'app/raw_recon_v7_source_selection.py':[
  ("if int(row.get(\"patch_added_line_count\") or 0) <= 0 or int(row.get(\"patch_removed_line_count\") or 0) <= 0:\n            continue",
   "if int(row.get(\"patch_added_line_count\") or 0) <= 0:\n            continue"),
 ],
 'app/v7_literal_patch_capture.py':[
  ("if not added or not removed:\n            raise RuntimeError(f\"{family}: upstream patch is not bidirectional\")",
   "if not added:\n            raise RuntimeError(f\"{family}: upstream merged patch has no added fix implementation\")"),
  ("\"vulnerable_or_removed_patch_lines\": removed[:80],",
   "\"vulnerable_or_removed_patch_lines\": removed[:80],\n                    \"positive_source_basis\": \"Fresh upstream security narrative is the positive proof; removed patch lines are supplemental when the fix replaces existing code.\","),
 ],
}
for rel,pairs in replacements.items():
 p=ROOT/rel;text=p.read_text()
 for old,new in pairs:
  if new in text:continue
  if old not in text:raise RuntimeError(f'anchor missing {rel}: {old[:100]}')
  text=text.replace(old,new,1)
 p.write_text(text)
 print('refined',rel)
