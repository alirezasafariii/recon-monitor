from __future__ import annotations

"""Runtime compatibility loader for the successful-snapshot boundary.

The production CLI imports ``recon_monitor_core``.  Keeping the established
implementation file untouched avoids a broad checksum/version change for this
focused reliability patch.  Python prefers this package over the sibling module,
so we execute the established implementation in this module namespace and then
replace only its Database binding with the snapshot-aware subclass.

Executing in the same namespace is important: later compatibility layers mutate
``recon_monitor_core.build_parser`` and related globals, and functions defined by
the established implementation must observe those mutations exactly as before.
"""

from pathlib import Path as _Path

_package_file = __file__
_impl_file = _Path(__file__).resolve().parent.parent / "recon_monitor_core.py"
_source = _impl_file.read_text(encoding="utf-8")

# The established module derives APP_DIR/ROOT_DIR from __file__. Temporarily
# expose its real path while compiling/executing, then restore package metadata.
globals()["__file__"] = str(_impl_file)
try:
    exec(compile(_source, str(_impl_file), "exec"), globals(), globals())
finally:
    globals()["__file__"] = _package_file

from successful_snapshot import SuccessfulSnapshotDatabase as _SnapshotDatabase

Database = _SnapshotDatabase
