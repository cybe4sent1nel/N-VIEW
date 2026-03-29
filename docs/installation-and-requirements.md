# Installation and Requirements

## Runtime Requirements

- Python 3.11+
- Nmap (N-VIEW can auto-attempt installation)
- Network access for AI providers (optional)

## Install Dependencies

```bash
python -m pip install -r requirements.txt
```

Optional editable install (adds Python entrypoint scripts):

```bash
python -m pip install -e .
```

## Bootstrap for Production

Run this once after install:

```bash
python -m nview.cli bootstrap
```

Bootstrap tasks:

- Detect platform (Windows/macOS/Linux + distro)
- Check if Nmap is installed
- Attempt automatic Nmap installation with available package manager
- Create launcher commands for `nview` and `n-view`
- Print manual installation commands if auto-install fails
- Print PATH instructions if launcher directory is not available globally

## Launchers and PATH

- Windows launchers: `%USERPROFILE%\\AppData\\Local\\nview\\bin`
- Linux/macOS launchers: `~/.local/bin`

If launcher directory is not on PATH, N-VIEW tells you what to add.
