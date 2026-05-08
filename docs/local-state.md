# Local State Directories

This document describes machine-local directories that exist in the working
tree but must never be committed to the repository.

## `.openclaw/`

Created automatically by the OpenClaw workspace bootstrapper. Contains
machine-local workspace state such as bootstrap timestamps and session
metadata (e.g. `workspace-state.json`). The data is specific to the local
clone and meaningless — or potentially privacy-sensitive — on any other
machine. **This directory must never be committed.** It is listed in
`.gitignore` to enforce that.

If you accidentally stage files from `.openclaw/`, run:

```bash
git rm -r --cached .openclaw/
```

Then verify `.gitignore` contains `.openclaw/` and commit the removal.
