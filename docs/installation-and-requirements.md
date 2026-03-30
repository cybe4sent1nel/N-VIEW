# Installation and Requirements

## Runtime Requirements

- Python 3.11+
- Nmap (N-VIEW can auto-attempt installation)
- Network access for AI providers (optional)

## Install Dependencies

```bash
python -m pip install -r requirements.txt
```

## OS Install Scripts

- Windows:

```powershell
./scripts/install_windows.ps1
```

- Linux:

```bash
bash ./scripts/install_linux.sh
```

- macOS:

```bash
bash ./scripts/install_macos.sh
```

- Linux/macOS auto-detect wrapper:

```bash
bash ./scripts/install.sh
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
- Trigger update sync from remote when available

## Launchers and PATH

- Windows launchers: `%USERPROFILE%\\AppData\\Local\\nview\\bin`
- Linux/macOS launchers: `~/.local/bin`

If launcher directory is not on PATH, N-VIEW tells you what to add.
If PATH was changed during setup, start a new terminal session.
