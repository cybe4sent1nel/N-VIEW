# N-VIEW

```text
███╗   ██╗      ██╗   ██╗██╗███████╗██╗    ██╗
████╗  ██║      ██║   ██║██║██╔════╝██║    ██║
██╔██╗ ██║█████╗██║   ██║██║█████╗  ██║ █╗ ██║
██║╚██╗██║╚════╝╚██╗ ██╔╝██║██╔══╝  ██║███╗██║
██║ ╚████║       ╚████╔╝ ██║███████╗╚███╔███╔╝
╚═╝  ╚═══╝        ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝
```

N-VIEW is a high-standard Nmap CLI companion focused on speed, clarity, and guided workflows.

**Tagline:** Professional Network Visibility, Simplified.

Developed by Fahad Khan (cybe4sent1nel)

Sponsor our project: fahadkhanxyz8816@gmail.com

## Demo Screenshots

![N-VIEW Demo 1](Screenshot%202026-03-29%20151637.png)
![N-VIEW Demo 2](Screenshot%202026-03-29%20151654.png)
![N-VIEW Demo 3](Screenshot%202026-03-29%20151800.png)
![N-VIEW Demo 4](Screenshot%202026-03-29%20151821.png)

## Highlights

- Guided number-based menus for easy usage
- Dedicated menu centers (Scan Center, Report Center, AI Settings, Tools)
- Natural-language scan intent normalization
- Scan profile presets for fast execution
- Cross-platform OS detection for runtime diagnostics
- Dependency checks with automatic Nmap install attempts
- Manual install fallback instructions when auto-install cannot complete
- Bootstrap command to prepare production runtime in one step
- Cross-platform command launchers for `nview` and `n-view`
- Detailed AI security report generation after scans
- In-terminal rendered AI report view (formatted markdown, not raw response)
- Primary AI provider: Cerebras
- Fallback AI provider: OpenRouter
- Environment-first configuration with `.env`

## Installation

```bash
python -m pip install -r requirements.txt
```

Optional package install for script entrypoints:

```bash
python -m pip install -e .
```

Run production bootstrap (recommended):

```bash
python -m nview.cli bootstrap
```

`bootstrap` performs:

- Platform detection (OS + Linux distro when available)
- Dependency validation
- Automatic Nmap installation attempts using detected package managers
- Launcher creation so `nview` and `n-view` can be called directly
- Clear manual installation commands when auto-install fails

## Run

```bash
python -m nview.cli
```

Or after package install:

```bash
nview
n-view
```

## Commands

```bash
python -m nview.cli --help
```

Available commands:

- `menu` - Full interactive mode
- `scan` - Direct non-interactive scan mode
- `configure-ai` - Configure provider, models, and keys
- `version` - Show branding/version banner
- `doctor` - Validate platform, dependencies, and provider/key setup
- `bootstrap` - Auto-prepare runtime dependencies and command aliases

## Environment Variables

N-VIEW loads `.env` automatically from the current working directory.

- `NVIEW_DEFAULT_PROVIDER` = `cerebras` or `openrouter`
- `CEREBRAS_API_KEY`
- `CEREBRAS_MODEL`
- `OPENROUTER_API_KEY`
- `OPENROUTER_MODEL`

See `.env.example` for template values.

## Typical Workflow

1. Run `nview`.
2. Open `Scan Center`.
3. Select scan profile by number.
4. Run scan.
5. Generate AI report.

Output goes to `./nview-results`.

## Production Notes

- During scans, N-VIEW auto-checks Nmap and attempts installation when missing.
- If installation fails due permissions/package manager constraints, N-VIEW prints OS-specific manual install commands.
- On Windows, `bootstrap` creates launchers under `%USERPROFILE%\\AppData\\Local\\nview\\bin`.
- On Linux/macOS, `bootstrap` creates launchers under `~/.local/bin` and tries to create `n-view` as a symlink to `nview`.
- If launcher directory is not on `PATH`, N-VIEW prints exactly what to add.
