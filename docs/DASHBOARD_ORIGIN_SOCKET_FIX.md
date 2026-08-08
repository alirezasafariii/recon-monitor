# Dashboard Origin Socket Fix

Version 6.0.2 adds a narrow fallback for local Dashboard POST validation.

The normal check still compares `Origin` with the HTTP `Host` header. When that fails and proxy-header trust is disabled, Recon Monitor checks the actual server socket. It accepts only when both the server and Origin are loopback addresses and the Origin port equals the real listening port.

This addresses Safari, privacy software, and local proxy setups that rewrite `Host` while preserving a valid local Origin. It does not disable CSRF protection and does not permit external origins.
