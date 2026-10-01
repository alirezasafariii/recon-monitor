# Update recovery

Update first verifies the package checksum and any supplied signature, extracts
the release into staging under the installation root, and copies all managed
program items there. Custom plugins are merged into this staged copy. Package
files cannot write through an existing plugin symlink outside staging.
Executable permissions are set before activation. A failure during extraction,
copying, or permission setup leaves the installed program unchanged.

Before activation, Update creates the normal data backup and a uniquely named
program archive. It also prepares a separate database snapshot under `state`,
on the database filesystem. Failed program archives are removed rather than
being advertised as usable backups. A failure preparing either backup or the
database snapshot prevents activation.

Each managed top-level program item is moved into a private `previous` directory
and replaced by its staged counterpart using filesystem renames. The original
tree stays available until initialization, compilation, unit tests, integration
tests, the success audit, and the rollback marker have all completed. The marker
continues to point to the previous successful backup when an update fails.

If activation fails, already moved items are restored by rename. If validation
or success recording fails, the exact previous program items are restored and
newly introduced items are removed. The live database connection is closed,
stale WAL/SHM sidecars are removed, and the prepared database snapshot is renamed
into place. Recovery does not need to copy the old program or database again
when the original failure was a full disk.

If automatic recovery itself fails, Update reports failure and retains the
recovery files, with their paths in the error message. A staging cleanup failure
after successful installation produces a warning without reporting the
committed update as failed.

`update rollback` extracts and checks the recorded program archive in staging
before replacing any installed item. It replaces the managed program snapshot
exactly, removing new-only code, plugins, and migration files. It does not
restore the data backup or replace user configuration, policy, or unrelated
files. An extraction or replacement failure keeps or restores the program that
was installed when rollback began.

The replacement is atomic for each renamed program item, not for the whole
installation at once. Handled failures and interruptions trigger recovery;
power loss or an uncatchable process kill does not automatically resume the
transaction. The retained program/data backups remain the recovery source in
that case.

Offline regression tests inject copy/disk-full errors, permission failures,
rename failures, validation failures/timeouts, interruptions, success-recording
failures, and recovery failures. They also verify plugin/configuration
preservation and exact explicit rollback.
