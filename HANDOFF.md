# Handoff — things only you can do

This list is maintained throughout the build. Items here need your credentials, accounts, or a human
decision — I can't (and shouldn't) do them for you. Nothing here blocks the build; it's what remains
for *you*.

## Pending

1. **Push to GitHub.** The repo is built locally with the remote wired
   (`https://github.com/dibakshya01/blue-kakapo`), but pushing needs your GitHub auth. When ready:
   ```bash
   git push -u origin main
   ```
   (If the remote already has commits, we'll reconcile first — tell me and I'll handle the merge.)

2. **Enable GitHub Actions** (if not on by default) so CI runs on push/PR.

3. **Container image / release.** The `Release` workflow (`.github/workflows/release.yml`) builds,
   SBOMs, **cosign-signs (keyless)**, and pushes the image to **GHCR** on a `v*` tag. To cut a release:
   ```bash
   git tag v0.0.1 && git push origin v0.0.1
   ```
   You may need to allow GitHub Actions to publish packages (repo → Settings → Actions → Workflow
   permissions) and make the GHCR package public.

4. *(Later)* Enable GitHub Pages for the project site; configure branch protection/rulesets on `main`.
   These are set up as we reach the site/launch stages.

## Notes

- A clone path **without spaces** is recommended for `uv run` (uv's editable install mishandles spaces
  in the directory path). CI and Docker are unaffected.
