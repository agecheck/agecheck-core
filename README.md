# @agecheck/core

[![CI](https://github.com/agecheck/agecheck-core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agecheck/agecheck-core/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40agecheck%2Fcore?label=npm)](https://www.npmjs.com/package/@agecheck/core)

`@agecheck/core` is the common TypeScript core used by AgeCheck SDK adapters.

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
