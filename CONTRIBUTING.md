# Contributing to Limekey

Thanks for your interest in contributing. Limekey is meant to become boring,
standard infrastructure — not a product with a moat. Contributions that push
toward spec compliance and away from vendor lock-in are the highest-value.

## Getting started

```bash
git clone https://github.com/your-org/limekey.git
cd limekey
npm install
npm test        # 87 tests, should all pass
npm run dev     # starts dev server with hot reload
```

## What to work on

**High-value contributions:**

- Spec compliance improvements (OAuth 2.1, RFC 9728, RFC 8707, MCP auth profile)
- New IdP adapter factories (Clerk, Stytch, Ory, Keycloak)
- Rego/OPA policy engine (v0.2 target)
- CIBA-based step-up approval (v0.2 target)
- Additional audit sinks (HTTP, S3, Kafka)
- Security hardening and edge-case handling
- Documentation improvements and examples
- Bug fixes with test cases

**Before starting large work**, open an issue to discuss the approach. This
avoids duplicate effort and lets us align on design before you invest time.

## Development workflow

1. **Fork and branch** — create a feature branch from `main`.
2. **Write tests first** — or at least alongside your code. We use
   [vitest](https://vitest.dev/). Tests live next to source files as
   `*.test.ts`.
3. **Check types** — `npx tsc --noEmit` must pass with zero errors.
4. **Run the full suite** — `npm test` must pass.
5. **Keep commits focused** — one logical change per commit.
6. **Open a PR** — describe what you changed and why. Link related issues.

## Code style

- TypeScript with `strict: true`.
- ESM modules — imports use `.js` extensions.
- Interfaces over classes where possible.
- Snake_case for external-facing schemas (audit events, policy rules) to
  match the spec. CamelCase for internal TypeScript APIs.
- Comments explain *why*, not *what*.

## Project structure

```
src/
  index.ts              gateway entrypoint
  config.ts             config loading + validation
  oauth/                token validation, RFC 9728
  policy/               policy engine + types
  stepup/               human approval hooks
  audit/                audit sink + types
  adapters/             IdP-specific factories
```

## Running tests

```bash
npm test                    # run all tests
npx vitest run src/config   # run specific test file
npx vitest --watch          # watch mode
```

## License

By contributing, you agree that your contributions will be licensed under
the Apache 2.0 License.
