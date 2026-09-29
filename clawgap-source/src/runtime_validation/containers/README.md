# Runtime qualification container definitions

These checked-in definitions are the pre-analysis source of truth for OCI builds. The builder
copies the declared `benchmark/` project and the ClawGap bridge into a temporary build context;
it never uses a benchmark checkout from outside the repository. Dynamic revision/source/lock
labels are supplied by the deterministic pre-analysis builder and verified before a baseline is
admitted.

Hermes Agent is the first smoke target, followed by the other selected benchmark projects. Python
containers use the pinned Python 3.12 base and benchmark dependency manifests. TypeScript containers
use pinned Node, Bun, and Python bases; package installation follows each benchmark lockfile and
runs during pre-analysis only.
