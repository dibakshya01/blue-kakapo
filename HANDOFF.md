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

3. *(Later)* Enable GitHub Pages for the project site, configure branch protection, and — only if you
   choose to — publish a package/release. These will be fleshed out as we reach those stages.

## Notes

- A clone path **without spaces** is recommended for `uv run` (uv's editable install mishandles spaces
  in the directory path). CI and Docker are unaffected.
