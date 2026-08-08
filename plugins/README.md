# Recon Monitor Plugin SDK

External plugins live in their own directory with `plugin.json` and a Python entrypoint.
Plugins must export an object named `plugin` implementing `healthcheck`, `plan`, and `execute`.
Active plugins must declare `requires_authorization: true`; the core authorization gates still apply.
