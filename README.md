# @agecheck/core

[![CI](https://github.com/agecheck/agecheck-core/actions/workflows/ci.yml/badge.svg)](https://github.com/agecheck/agecheck-core/actions/workflows/ci.yml)
[![Publish](https://github.com/agecheck/agecheck-core/actions/workflows/publish.yml/badge.svg)](https://github.com/agecheck/agecheck-core/actions/workflows/publish.yml)

`@agecheck/core` is the security-critical core used by AgeCheck SDK adapters.

It contains:

- token verification (`verifyAgeToken`)
- gate policy (`isGateRequired`)
- signed verification cookie helpers
- typed domain errors and models

Most hostmasters should use `@agecheck/node` directly. Consume `@agecheck/core` only if you are building a framework adapter or platform integration.

## Install

```bash
pnpm add @agecheck/core
```

## Quality gates

```bash
pnpm typecheck
pnpm test
pnpm build
```

## Notes

- Runtime requirement: Node 20+
- Module format: ESM + CJS output from `dist/`
- Versioning and release policy: `/docs/VERSIONING.md`
