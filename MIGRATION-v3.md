# Upgrade to Recon Monitor 3.0.0

Use the supplied one-file patch or run `upgrade-v3.sh` from the extracted release.

```bash
bash upgrade-v3.sh ~/Downloads/recon-monitor
```

The upgrade refuses to continue while a recon run lock is active, creates a timestamped program backup, creates a consistent SQLite safety backup when possible, and preserves user data:

- `config.env`
- `targets.txt`
- `policies/targets.json`
- `recon.db`
- `state/`
- `output/`
- `reports/`
- `logs/`
- user-created plugins under `plugins/`

On initialization, SQLite migrates automatically to schema 7. Existing baselines, runs, alerts, tags, notes, Telegram configuration, target policies, and evidence remain intact.

After upgrading:

```bash
cd ~/Downloads/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh doctor
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
./recon-monitor.sh run --target YOUR_TARGET --dry-run
```

Expected version:

```text
3.0.0
```

Create or migrate an RBAC dashboard administrator:

```bash
./recon-monitor.sh dashboard auth-set --username admin
./recon-monitor.sh dashboard restart --open
```

The upgrade stops background Dashboard/API processes before replacing program files. Restart them after verification.
