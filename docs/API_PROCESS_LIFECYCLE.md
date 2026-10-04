# Local API process identity

The local API stores its PID record at `state/api.pid`. A PID is only a
locator. `api status` checks this installation's `app/recon_monitor.py api
foreground` command, its control instance, and its Linux start token when
available. Checkout paths containing spaces are supported in both Linux
argument records and macOS `ps` output.

Each `api start` generates a new random 128-bit control instance and passes it
to the child through an internal CLI option. The atomically written version-2
PID record contains `pid`, `start_token` and `control_instance`, with file mode
`0600`. The control instance is a local shutdown capability, separate from
HTTP authentication and API bearer tokens.

On Linux and macOS, new instances stop cooperatively through
`state/api-stop-<control_instance>.json`. The API polls only its own instance's
file and accepts a stop request only for that instance and its own PID. It
shuts down its serving loop, closes the listener, and then acknowledges the
same instance and PID. `api stop` reports success only after that acknowledgement;
no numeric PID receives `SIGTERM` or `SIGKILL` on this path. PID reuse cannot
redirect a stale request to another instance, including one running the same
API command. The control file is written atomically with mode `0600`; this adds
no HTTP route, network request, or API-token requirement.

If the acknowledgement does not arrive within the existing three-second stop
wait, or the stop request cannot be written, stop reports an error and retains
the PID record and any existing request. It does not fall back to signalling a PID. A later
retry accepts a delayed acknowledgement even after the original process has
exited. Cleanup compares the captured PID record with its current contents,
so a replacement record observed during shutdown is preserved. If record
cleanup fails, the acknowledgement remains available for retry.

Legacy integer and JSON PID records remain readable. A legacy API can be
stopped automatically only when a Linux start token and both `pidfd_open` and
`pidfd_send_signal` are available. Identity is checked again after opening
the pidfd; that same descriptor is held through `SIGTERM`, exit confirmation,
and any `SIGKILL` escalation. If pidfd acquisition or signalling fails, there
is no `os.kill(pid, sig)` fallback and the PID record remains. On macOS or
another platform without pidfds, an API already running from an older version
must be stopped through its owning terminal or service before using the new
`api start`. Checking command/path and then signalling a bare PID is not safe.

Regression tests exercise missing Linux facilities, PID reuse, delayed and
invalid acknowledgements, record replacement, file-write and pidfd failures,
and escalation through one descriptor. Real loopback-only server and child
fixtures verify listener closure and absence of shutdown deadlocks without
performing reconnaissance or external network requests. CI also runs the API
regressions on macOS.
