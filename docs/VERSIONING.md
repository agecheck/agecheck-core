# Versioning and Release Policy

## SemVer policy

`@agecheck/core` follows Semantic Versioning.

- `MAJOR`: breaking API or behavior changes
- `MINOR`: backward-compatible feature additions
- `PATCH`: backward-compatible fixes and hardening

## Security-sensitive change policy

Any change that affects verification semantics, issuer trust defaults, cookie format, or session binding behavior must include:

- explicit changelog note
- test coverage for happy + failure paths
- review confirmation before publish

## Release checklist

1. `pnpm install --frozen-lockfile`
2. `pnpm typecheck`
3. `pnpm test`
4. `pnpm build`
5. bump version
6. tag release
7. publish from CI workflow
