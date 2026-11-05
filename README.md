# Native Windows ACL checks for Crystal

A small test snapshot of `filesystem-access-control` and its
`filesystem-capabilities` dependency. It contains source, selected Windows
specs, native probes and the behavior runner. It is not the full shard
workspace or a release package.

The two source directories are siblings under `source/`. Their MIT notices
are retained separately. Tests use that vendored dependency through
`CRYSTAL_PATH`; they do not fetch the dependency named by the original shard
manifest. `SOURCE-MANIFEST.sha256` identifies the copied files.

The dispatch-only workflow uses the standard public `windows-2022` and
`windows-2025` runners with Crystal 1.21.0 and 1.22.2. It has no paid runner,
cache or artifact-upload step. Official compiler ZIPs are pinned by SHA-256.
The official Windows compiler assets are labelled unsupported by Crystal.

Every job stages its sources and builds under `RUNNER_TEMP`. It runs the
selected specs, descriptor/token probes, and six native behavior cases in
fresh bounded helpers. Structured receipts are printed to job logs with the
`ACL_RECEIPT` prefix. A timeout, crash, malformed response or incomplete
completion is a harness failure; it never implies that a mutation was rejected
or that no mutation occurred.

The probes exercise held object identity, explicit non-NULL DACL replacement,
readback verification, directory propagation, discretionary AccessCheck,
fresh native acquisition/I/O, and deny-only/restricting token controls. The
library never changes caller credentials; disposable probes do so explicitly.
Results qualify those fixtures and the recorded host/toolchain, not all ACL
semantics, token contexts, filesystems or remote servers.

This snapshot starts from local shard baselines `654201e`
(filesystem-access-control) and the recorded source manifest, including
uncommitted API and verification improvements. Hosted evidence belongs to the
exact snapshot commit that ran. Sources are maintained in their own projects;
fixes discovered here are applied there before refreshing the snapshot.
