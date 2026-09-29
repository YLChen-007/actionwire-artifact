# Synthetic Nanobot login-shell fixture

This fixture models a minimal source backport onto Nanobot `v0.1.4.post5`:
the child receives a reduced environment that preserves `HOME`, while the
model-controlled command executes through `bash`/`zsh -l -c`. Loading the real
user profile can reintroduce values excluded from the explicit environment.

It is detector-regression evidence only. It is not present in the pinned
revision and must not be counted as revision-bound empirical coverage.

Run from the repository root:

```bash
bin/codeql test run --threads=1 --additional-packs=src/ql -- \
  src/ql/tests/nanobot_login_shell_synthetic
```

Build the full source derivative with:

```bash
python scripts/build_nanobot_login_shell_synthetic.py
```
