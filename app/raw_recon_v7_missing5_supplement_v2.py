from __future__ import annotations

# Analysis 6.32 v7: the four already committed patchable missing-family sources
# are revalidated under the current firewall/semantic/condition gates, while
# graphql_data_exposure is fetched from a fresh merged upstream security PR.
# This avoids repeating broad GitHub search queries without weakening any gate.
from raw_recon_v7_missing5_fast_revalidate import main


if __name__ == "__main__":
    raise SystemExit(main())
