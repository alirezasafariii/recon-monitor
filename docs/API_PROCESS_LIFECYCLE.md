# Local API process identity

The local API stores its PID record at `state/api.pid`. A PID is only a
locator, so status and stop validate the process command before trusting it:
the command must point to this installation's `app/recon_monitor.py` and run
`api foreground`. This prevents a stale PID file from describing or stopping
an unrelated process after PID reuse.

New API starts store a JSON record with the PID and the Linux `/proc` process
start token. Existing installations with a plain integer PID file remain
readable and are checked by command identity. When the start token is
available, a changed token rejects the record even if the PID now runs the
same API command.

On Linux with `pidfd_open` and `pidfd_send_signal`, `api stop` signals the
process instance referenced by the pidfd. It rechecks the start token after
opening the pidfd. On systems without pidfds, it performs the same identity
checks and uses the platform's normal signal API. A mismatch, missing process,
or unreadable command removes the stale PID record and sends no signal.

The PID record is written atomically after the child process is created. The
API log remains separate, and the record does not contain credentials or API
tokens. The service command and port are still taken from the foreground
process arguments, so status reports the actual endpoint represented by the
record.

The regression suite covers unrelated live PIDs, legacy records, same-command
PID reuse with a different start token, exact checkout command matching, and
writing the new record format.
