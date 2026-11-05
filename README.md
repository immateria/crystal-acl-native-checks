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
`windows-2025` runners with Crystal 1.21.0 and 1.22.2. It uses no paid runner
or cache. Official compiler ZIPs and the artifact-upload action are pinned.
The official Windows compiler assets are labelled unsupported by Crystal.

Every job stages its sources and builds under `RUNNER_TEMP`. It runs the
selected specs, descriptor/token probes, and eight native behavior cases in
fresh bounded helpers. Structured receipts are printed to job logs with the
`ACL_RECEIPT` prefix. Each job also uploads a compressed evidence bundle with
one-day retention and a 16 MiB limit before compression. A timeout, crash,
malformed response or incomplete completion is a harness failure; it never
implies that a mutation was rejected or that no mutation occurred.

Evidence collection runs after successful and failed native steps. It copies
allowlisted JSON receipts and original bounded stdout/stderr files into a
separate directory. The export manifest records hashes, sizes, omissions and
collection errors. A collection failure leaves the native result unchanged
and fails the collection step. Source trees, compilers, executables, caches,
environment files and reparse paths are excluded. Failure before checkout or
termination of the entire job can prevent artifact collection.

The probes exercise held object identity, explicit non-NULL DACL replacement,
readback verification, directory propagation, discretionary AccessCheck,
fresh native acquisition/I/O, and deny-only/restricting token controls. The
library never changes caller credentials; disposable probes do so explicitly.
Results qualify those fixtures and the recorded host/toolchain, not all ACL
semantics, token contexts, filesystems or remote servers.

This snapshot builds on shard checkpoint `bbc583d`
(filesystem-access-control), with additional propagation qualification cases
identified by the source manifest. Hosted evidence belongs to the
exact snapshot commit that ran. Sources are maintained in their own projects;
fixes discovered here are applied there before refreshing the snapshot.

On 2026-11-05 (UTC), [snapshot a65279b](https://github.com/immateria/crystal-acl-native-checks/commit/a65279b75119d62680cba74b1bec10b2658d42a8)
passed [all four native Windows cells](https://github.com/immateria/crystal-acl-native-checks/actions/runs/41965719924):
106 specs, two probes and six behavior cases per cell. Restricted-token
qualification covers controlled parent-relative acquisition and data I/O;
the restricting-positive absolute and reopen routes remain unqualified.

The workflow preserves checkout line endings and verifies every published
source-manifest hash before testing. The added propagation fixtures cover
protected barriers, grandchildren, and mixed outcomes when an exclusive directory
handle prevents enumeration. A separate failed parent setter retains independent
parent and child readbacks. Simulated failure after partial effects remains
provider/state-machine evidence, not a native failure reproduction.
