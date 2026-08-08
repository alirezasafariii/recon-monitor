# Recon Monitor v8.4.5

Current Analysis Projection Isolation hotfix.

- Current Change Intelligence now reads candidate highlights only from the latest analysis for the target.
- Current Attack Surface Graph now projects candidate nodes only from the latest analysis.
- Historical candidate memory, target learning, and analyst history remain preserved and queryable.
- No database schema change; schema remains 18.
- This prevents historical candidates from reappearing as current findings after a newer analysis correctly abstains.
