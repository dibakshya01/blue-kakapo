# Handoff — things only you can do

This list needs your credentials, accounts, or a human decision — I can't (and shouldn't) do these for
you. Everything up to the final click is done.

## Status at handoff

- **Built, tested, hardened, documented.** 153 tests pass; `ruff` + `ruff format` + `mypy` (75 files) +
  the dashboard's `tsc`/`vite` build are all clean. README quickstart (`bk info` / `serve` / `triage` /
  `eval`) reproduces offline with no key.
- **Adversarial hardening: 5 back-to-back rounds** (fresh, memory-free reviewers), each finding's fix
  carrying a fail-before/pass-after test. The final round came back essentially clean. Full per-round
  findings + fixes are in [`BUILD_LOG.md`](BUILD_LOG.md).
- **~26 commits, local only. Nothing has been pushed** and nothing public has been created — the remote
  is wired but your GitHub auth is required to push (item 1).
- The landing page is animated/interactive (motion layer, verified on desktop + mobile).
- Launch posts (Show HN, Reddit, socials + an honest FAQ) are drafted for you in `LAUNCH.md`
  (git-ignored). Nothing has been posted.

## Pending (yours)

1. **Push to GitHub.** The remote is wired (`https://github.com/dibakshya01/blue-kakapo`); pushing needs
   your auth:
   ```bash
   git push -u origin main
   ```
   (If the remote already has commits, tell me and I'll reconcile/merge first.)

2. **Enable GitHub Actions** (if not on by default) so CI (`.github/workflows/ci.yml`:
   ruff + format + mypy + pytest on 3.11/3.12) runs on push/PR.

3. **Container image / release.** `.github/workflows/release.yml` builds, generates an SBOM,
   **cosign-signs (keyless)**, and pushes to **GHCR** on a `v*` tag:
   ```bash
   git tag v0.0.1 && git push origin v0.0.1
   ```
   You may need to allow Actions to publish packages (repo → Settings → Actions → Workflow permissions)
   and make the GHCR package public.

4. **Enable GitHub Pages.** Repo → Settings → Pages → Source = `main` branch, `/docs` folder.
   Publishes the animated site at `https://dibakshya01.github.io/blue-kakapo/`.

5. **Set the social preview card.** Repo → Settings → Social preview → upload
   [`docs/assets/social-card.jpg`](docs/assets/social-card.jpg).

6. **Branch protection on `main`** (Settings → Rules): require CI + a review before merge.

7. **Launch when ready.** Post the drafts in `LAUNCH.md` yourself (Show HN / r/netsec / socials). Be
   around for the first couple of hours to answer — expect questions on false negatives and prompt
   injection; the docs and the FAQ in `LAUNCH.md` answer them straight.

## Notes

- Clone to a path **without spaces** for `uv run` (uv's editable install mishandles a space in the
  directory path; CI and Docker are unaffected). This working copy lives under "OpenSource Projects/",
  so tests here run via `PYTHONPATH=src`.
- Auth is **off by default** for localhost; `bk serve` refuses a non-loopback bind while auth is off
  (override `--insecure` / `BK_ALLOW_INSECURE_BIND=1`). Turn on `BK_AUTH_ENABLED=1` + tokens/OIDC for
  any deployment.
- GDPR erasure is pattern/observable-based (not NER) and is scoped honestly in `docs/gdpr-erasure.md`;
  `POST /api/cases/{id}/erase?confirm=true` (admin) is the subject-erasure endpoint.
