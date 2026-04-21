# Contributing to netrecon

Thanks for considering a contribution. netrecon is a small, opinionated project
— the bar is quality over quantity.

## Ground rules

1. **Tests pass before you open a PR.** `npm test` — 116+ tests. Add tests for
   new findings, new providers, and any change to input handling.
2. **No secrets in code.** All credentials go through Pages environment
   variables. `.env.local` and `.dev.vars` are gitignored.
3. **Keep `/about` promises truthful.** The product is marketed as "no ads, no
   email-gated reports, no tracking beyond privacy-respecting analytics."
   Changes that conflict with this need a discussion first.
4. **Findings must be actionable.** Every new correlation rule in
   `src/lib/findings` must include a reproducible command (`dig`, `curl`,
   `openssl`) the user can run to verify.
5. **Respect upstream rate limits.** Shodan is paid; Certspotter is
   rate-limited. New providers should include graceful skip-on-error.

## What we're looking for

Good fits:

- New correlated findings (rules that combine signals across DNS/HTTP/TLS/email/CDN).
- New data providers with clear, documented limits.
- UI/UX polish that preserves the terminal aesthetic.
- Blog posts on real investigations you used netrecon for.
- Documentation improvements.

Not-so-good fits:

- Monitoring / alerting features — out of scope for the free tier.
- UI framework rewrites — Astro + inline scripts is intentional.
- Tracking / ads / email capture — non-goals.

## Development

```bash
npm install
npm run dev          # Astro dev server (no Pages Functions)
npm run preview      # wrangler pages dev ./dist (full stack)
npm test
npm run typecheck
```

## Filing issues

- Bugs: include input, expected vs actual output, and the request ID from the
  report footer if available.
- Feature requests: include the use case ("as an SRE investigating X I want Y
  so that Z") — not just the feature.
- Security vulnerabilities: see [SECURITY.md](./SECURITY.md). Do **not** open a
  public issue.

## Code style

Match what's there. TypeScript `strict`, no `any`, 2-space indent. If
something's ambiguous, mirror the nearest existing module.

## License

Contributions are released under the project's [MIT License](./LICENSE).
