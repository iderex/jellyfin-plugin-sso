# What & why

<!-- What does this change do, and why? Link the issue: Closes #NNN -->

## Type of change

- [ ] Security hardening / vulnerability fix
- [ ] Bug fix
- [ ] Feature
- [ ] Refactor / code quality / docs

## Security checklist

Fill in for any change touching the login path, crypto (SAML/OIDC), config
persistence, or the release pipeline.

- [ ] Fail-closed preserved: a missing signature, time-bound, or audience is
      rejected, never default-accepted.
- [ ] No secrets logged; secrets are redacted on config export.
- [ ] A security review was performed for changes to SAML/OIDC validation,
      config persistence, or the release pipeline.
- [ ] Log inputs from the IdP are sanitized inline at the log call.

## Quality checklist

- [ ] No duplicated logic; new logic lives in a small, single-purpose,
      testable unit.
- [ ] The change adds no more code than the problem requires.

## Verification

- [ ] `dotnet build --no-restore --warnaserror` is green.
- [ ] `dotnet test` is green.
- [ ] Prettier is clean for any `.js` / `.html` / `.md` / `.css` change.

## Notes

<!-- Trade-offs, follow-ups, or anything explicitly out of scope. -->
