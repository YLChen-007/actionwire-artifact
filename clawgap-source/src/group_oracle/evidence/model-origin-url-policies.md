# Model-origin URL policy contracts (v1)

These reviewed documentation contracts preserve security objectives already present
in the four analysis-pinned member IR records listed below. They are supplemental
normative evidence for the targeted URL-group repair, not a new capability card and
not a claim that every network tool implements every policy. The checked subject
must have an explicit model-origin binding. Configuration is a comparison policy,
not a model-origin subject.

The analysis revision labels identify the input snapshot; they are not independent
proof of upstream Git blobs. Gate IR and code locators were checked against the
CodeQL source archives during review. No ground-truth vulnerability labels or target
candidate verdicts are used in these contracts.

## url-secret-pattern-block

When model-origin URL arguments are submitted to an external content-retrieval service, reject the entire invocation before any backend dispatch if any raw URL or its once-percent-decoded form matches a protected, recognized secret-token pattern. The matching policy is the configured or versioned set of recognized token patterns and boundaries; this does not claim detection of every secret or require changing the URL contents. An unmatched URL does not by itself satisfy any independent destination policy.

Binding: Hermes Agent `web_extract_tool`, recorded revision
`04439ac77f08915b4886bc3c79165a9538af6219`, chains
`C-2aa79d9ca43d` and `C-46727898f25d`, gate
`GUfa8fbd80e924f0481119`. Its input explicitly binds `_url` to an element
of the model's `urls` parameter; `default` includes the once-decoded sibling check.
Code locator: `tools/web_tools.py:1283-1302`; the call returns an error for the
entire invocation before constructing and dispatching the safe-URL list.

## url-address-prefilter

When a member prefilters model-origin URLs before submission to an external content-retrieval service, only URLs admitted by that destination policy may be submitted. Reject missing hostnames, the policy's always-blocked metadata hostnames, and any resolved address in its always-blocked IP/network set regardless of private-address opt-outs. Reject ordinary private/internal addresses unless the policy explicitly permits private addresses or the URL matches its trusted-HTTPS-host exception. DNS failure and otherwise unhandled validation exceptions reject the URL. Filter rejected URLs individually and submit only the remaining safe URLs; submit none when none remain. This is a local prefilter, not a guarantee about the retrieval service's later DNS resolution or redirects.

Binding: the same two Hermes Agent chains, gate `GU1ed6874487204858ee3a`.
The input explicitly binds `url` to `urls` list elements. Its steps distinguish
always-blocked sets from private-address exemptions, including a trusted HTTPS
hostname exception; invalid individual IP strings are skipped in the recorded
resolution loop, not asserted to trigger an additional rejection.
Code locators: `tools/web_tools.py:1324-1345`, `tools/url_safety.py:251-327`.
The always-blocked network in this snapshot includes IPv4 `169.254.0.0/16`;
the contract does not turn all private-address exceptions into metadata exceptions.

## configured-website-blocklist

When a member with an enabled, successfully loaded website-blocklist policy downloads a model-origin URL, reject the request before the HTTP call if the normalized hostname matches an active blocked rule, using the policy's exact-host, dot-suffix or wildcard matching semantics. This obligation applies only to members and configurations that provide that policy. A public IP address or an allowed HTTP scheme does not exempt a hostname blocked by the active website policy.

Interpretation boundary (not a separate required check): policy-disabled, cache and
load-error behavior remain recorded enforcement limits. The observed default-path
load-error allow behavior is neither a new mandatory fail-open policy nor authority
to invent fail-closed handling. Other group members need not introduce a blocklist.

Binding: Hermes Agent `_handle_vision_analyze`, recorded revision
`04439ac77f08915b4886bc3c79165a9538af6219`, chain `C-806a548b73e2`, direct
gate `GU1228344ddaf94b9b1c88` and its result branch `GUb5d69a74580bb70abd74`.
The direct gate input explicitly identifies `image_url` as args-derived and bound
to the validator's URL formal; the branch checks its returned block metadata.
Code locators: `tools/vision_tools.py:483-491`, `tools/website_policy.py:209-282`.
The other member, ChatGPT-on-WeChat `C-cc8199b82f91`, has no recorded blocklist
policy and must not receive an unconditional blocklist requirement. Cache-disabled
short-circuiting and failed policy loading are limitations, not new safety promises.

## remote-image-url-admission

When a member admits a model-origin image URL to its remote HTTP download branch, require an HTTP or HTTPS scheme. For members using the recorded private-address admission policy, reject missing hostnames, always-blocked metadata hostnames and addresses in the always-blocked IP/network sets regardless of private-address opt-outs; reject ordinary private/internal addresses unless the policy explicitly permits private addresses or the hostname qualifies for its trusted-HTTPS exception, and reject DNS failures and otherwise unhandled URL-validation exceptions.

Interpretation boundary (not a separate required check): this remote-URL obligation
does not prohibit a separate supported local-image branch. URL/DNS validation and
website-policy configuration loading are different checks; a configuration load-error
allow path does not override an independent URL/DNS rejection.

Binding: G25's model-origin image URL admission already appears in the input.
Hermes Agent `C-806a548b73e2`, gate `GUd41b18fdd81044c24697`, explicitly binds
`image_url` as args-derived and records scheme, hostname/IP and DNS checks before
network download. ChatGPT-on-WeChat `C-cc8199b82f91`, gate
`GUb6fd39b96570f9649480`, records scheme-based remote-branch selection; that does
not establish that this member implements the Hermes address or blocklist policy.
Code locators: `tools/vision_tools.py:76-104,472-495`,
`agent/tools/vision/vision.py:566-600`. This evidence preserves the existing
remote-URL safety objective while repairing the independent blocklist omission.
