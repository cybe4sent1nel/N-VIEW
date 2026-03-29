# Troubleshooting and FAQ

## Nmap not found
Run:

```bash
python -m nview.cli bootstrap
```

If auto-install still fails, use the manual install command shown by `bootstrap` or `doctor`.

## nview command not found

Run bootstrap to create launchers:

```bash
python -m nview.cli bootstrap
```

Then add launcher directory to PATH if needed:

- Windows: `%USERPROFILE%\\AppData\\Local\\nview\\bin`
- Linux/macOS: `~/.local/bin`

## AI report failed
Check provider keys in `.env` and verify network access.

## Where are outputs saved?
`./nview-results` in the working directory.
