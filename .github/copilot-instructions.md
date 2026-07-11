# Project context for code review

This repository is a Jellyfin authentication plugin (C# / .NET 9) that signs
users in through OpenID Connect and SAML 2.0. Nearly every change touches a
login path, so review with a security-first mindset: a bug here is an
authentication bypass, not an inconvenience.

## Review priorities

1. **Fail closed.** Validation must reject on anything missing, unparseable,
   or unexpected — a missing signature, time bound, audience, state, or role
   must never default to accept. Flag any default-accept branch, swallowed
   exception, or early return that skips a validation step.
2. **Secrets stay secret.** `OidSecret`, signing keys, state tokens, and PKCE
   verifiers must never appear in logs, error messages, API responses, or
   config exports. Flag any new serialization of configuration or state.
3. **Log forging.** Request- or identity-provider-controlled values are
   sanitized inline at the log call with `?.ReplaceLineEndings(string.Empty)`.
   A sanitizer hidden behind a helper method is not recognized by CodeQL —
   flag it.
4. **Concurrency.** Plugin configuration is mutated only through
   `SSOPlugin.MutateConfiguration` / `ReadConfiguration`; shared state on the
   login path must be safe under concurrent requests, and check-then-act
   sequences on shared collections should be atomic.
5. **Release pipeline.** The MD5 `.md5` sidecar produced by the publish
   workflow feeds the Jellyfin plugin manifest checksum. Flag any workflow
   change that drops or renames it.

## Conventions

- C# is StyleCop-clean and builds with `--warnaserror`; public members carry
  XML doc comments. Prefer small single-responsibility helpers behind a thin
  controller, and the least code that does the job — call out duplication and
  dead code.
- Tests are xUnit v3. A security-relevant change needs a negative test (the
  reject path), not only the happy path.
- Web assets (`.js`, `.html`, `.css`, `.md`) are Prettier-formatted;
  `*.min.js` is vendored and exempt.
- All repository artifacts are written in English. Commit subjects are short
  and imperative, without a conventional-commit prefix.

## Suggestions

Prefer small, targeted diffs over rewrites. Call out anything that changes
user-facing behavior, configuration, or the security posture so the
documentation (README, providers.md, wiki) can be updated in the same pull
request.
