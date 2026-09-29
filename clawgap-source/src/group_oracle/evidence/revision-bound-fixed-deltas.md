# Revision-bound fixed-delta evidence

This registry source records reviewed security obligations from the repository's
revision-pinned static acceptance and oracle contracts. It is normative evidence for
group-oracle construction, not a substitute for current-chain rebasing. Every application is
also restricted by exact HC and ST identifiers in `oracle-evidence-registry.json`.

## NanoBot v0.1.4.post5 (`337c4600f3d78797bb4ed845b5a02118c7ac2d00`)

- `exec-allow-pattern-shell-chain`: A raw regex prefix match does not authorize every executable component interpreted by a shell command sink.
- `exec-comment-tail-and-workspace-semantics`: Shell authorization and workspace confinement must account for comments, expansions, substitutions, and the effective executed command domain.
- `exec-wrapper-prefix-allowlist`: Authorization of a shell command must cover the complete parsed command rather than only a wrapper prefix.

Source contract: `design/nanobot/nanobot-v0.1.4.post5-acceptance.json`.

## QwenPaw v1.1.10 (`6d1e936f1ba08ad2e0398367f8c27529e9d1d5df`)

- `shell-jq-env-guard-gap`: A shell-command credential policy that restricts environment access must cover jq environment-object access, not only procfs, system calls, and file flags.
- `request-context-tool-guard-bypass`: Bypassing a command guard requires trusted, authenticated request-context provenance rather than an untrusted external context marker.
- `managed-cdp-local-control`: A model-controlled local CDP endpoint that launches a browser process requires peer authentication or an equivalently restrictive access boundary.

Source contract: `design/QwenPaw/qwenpaw-v1.1.10-acceptance.json`.

## CowAgent 2.0.8 (`43c71a7787f9b54b76cbc66dffcfe0809b44086c`)

- `bash-missing-approval`: Model-controlled Bash execution requires a mandatory user approval checkpoint before process creation.
- `read-procfs-alias`: A sensitive-file read policy must reject procfs credential aliases that bypass pathname-only checks.

Source contract: `design/chatgpt-on-wechat/groundtruth/cowagent-2.0.8-acceptance.json`.

## AstrBot 4.25.2 (`d3ecb74babbb6e4eeb80c59a5c8051c7128382d0`)

- `workspace-hardlink-alias`: Workspace confinement for file reads must validate filesystem-object or inode identity so hardlink aliases cannot escape the allowed object boundary.

Source contract: `design/AstrBot/astrbot-4.25.2-acceptance.json`.

## NanoClaw (`d7357f827286be2ea9d6eb94fa97b347086a4ca4`)

- `NCOR-bf5b84f58d2d3bc1`: A model-controlled file-copy destination must be lstat/realpath-resolved and contained within the permitted target inbox before copying.
- `NCOR-6040ea5ff49cc74d`: A model-controlled file-copy source must resolve within the permitted workspace or root boundary before copying.

Source contract: `design/nanoclaw/inventory/nanoclaw-static-oracle.json`.

## OpenClaw-CN (`1b58920cfb26bf915c79e4fca536eb880b2d191b`)

- `OCN-SINK-5b33be4c77c65fba`: A model-controlled remote-media URL must receive SSRF destination validation before network retrieval.
- `OCN-SINK-900ffc5993b6aeb2`: After a browser action can navigate, the resulting destination must be revalidated before subsequent browser access.

Source contract: `design/openclaw-cn/inventory/openclaw-cn-static-oracle.json`.
