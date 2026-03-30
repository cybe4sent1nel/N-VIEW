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

Sponsor our project- donate through paypal: fahadkhanxyz8816@gmail.com

## Demo Screenshots

![N-VIEW Demo 1](Screenshot%202026-03-29%20151637.png)
![N-VIEW Demo 2](Screenshot%202026-03-29%20151654.png)
![N-VIEW Demo 3](Screenshot%202026-03-29%20151800.png)
![N-VIEW Demo 4](Screenshot%202026-03-29%20151821.png)

## Highlights

- Guided number-based menus for easy usage
- Dedicated menu centers (Scan Center, Discovery Center, Local System Scan, Report Center, AI Settings, Tools)
- Natural-language scan intent normalization
- Scan profile presets for fast execution
- Advanced non-interactive scan tuning (`--ports`, `--top-ports`, `--timing`, `--udp`, `--os-detect`, `--scripts`, `--no-ping`)
- Target file support (`--target-file`) for multi-target operations
- Dedicated local system scan command (`system-scan`) and menu workflows
- Dedicated discovery command (`discover`) and discovery submenu workflows
- Resilient scan retries (`--retries`) for transient failures
- Multi-format scan artifacts (XML, NMAP, GNMAP)
- Built-in scan history viewer (`history`)
- Visual exposure analytics: threat score, service distribution bars, host exposure heatmap
- Prioritized remediation recommendations with high-risk port indicators
- Offline XML intelligence mode via `analyze`
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
- Cross-directory AI config persistence: values from `.env` are stored and reused globally until changed

## Installation

```bash
python -m pip install -r requirements.txt
```

One-command OS installers (recommended):

- Windows (PowerShell):

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

- Auto-detect wrapper (Linux/macOS):

```bash
bash ./scripts/install.sh
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
- PATH wiring for global `nview` and `n-view` invocation
- Launcher generation with absolute app entry so commands work from any directory

## Run

```bash
python -m nview.cli
```

Or after package install:

```bash
nview
n-view
```

If commands are not recognized in an existing terminal, open a new terminal session after installation/bootstrap.

## Commands

```bash
python -m nview.cli --help
```

Available commands:

- `menu` - Full interactive mode
- `scan` - Direct non-interactive scan mode
- `system-scan` - Local system open-port scan with profile selection
- `discover` - Discovery-only scan (`-sn`) for host/CIDR targets
- `configure-ai` - Configure provider, models, and keys
- `version` - Show branding/version banner
- `doctor` - Validate platform, dependencies, and provider/key setup
- `bootstrap` - Auto-prepare runtime dependencies and command aliases
- `history` - Show recent scan records and generated artifact availability
- `analyze` - Visualize and prioritize findings from existing Nmap XML files
- `report` - Render saved AI report markdown in terminal with rich formatting
- `update` - Pull latest changes from remote and refresh dependencies

## Environment Variables

N-VIEW loads `.env` from multiple sources and persists effective values to user config for cross-directory usage.

Load order:

1. `~/.config/nview/.env`
2. `<repo>/.env`
3. `<current working directory>/.env`

Then values are merged into `~/.config/nview/config.json` so your API keys/models stay available even if you run from another folder.

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

## Advanced Examples

Single target with advanced controls:

```bash
nview scan --target 192.168.1.10 --nl "quick scan" --timing 4 --top-ports 500 --scripts default,safe --retries 2
```

Multi-target file scan:

```bash
n-view scan --target-file targets.txt --flags "-sV -Pn" --udp --os-detect --xml-only --no-ai
```

Local system scan:

```bash
nview system-scan --profile quick --ai
```

Discovery scan:

```bash
nview discover --target 192.168.1.0/24
```

Show recent history:

```bash
nview history --limit 30
```

Analyze existing XML:

```bash
nview analyze --xml ./nview-results/target_20260329_120000.xml
```

Render latest AI report in terminal (formatted, not raw markdown):

```bash
nview report --latest
```

## Auto Update

- On startup, N-VIEW checks `origin/main` for updates.
- If updates are found and your working tree is clean, it fast-forwards and syncs dependencies.
- To disable auto update check for a session:

```bash
set NVIEW_DISABLE_AUTO_UPDATE=1
```

Manual update:

```bash
nview update
```

## Production Notes

- During scans, N-VIEW auto-checks Nmap and attempts installation when missing.
- If installation fails due permissions/package manager constraints, N-VIEW prints OS-specific manual install commands.
- On Windows, `bootstrap` creates launchers under `%USERPROFILE%\\AppData\\Local\\nview\\bin`.
- On Linux/macOS, `bootstrap` creates launchers under `~/.local/bin` and tries to create `n-view` as a symlink to `nview`.
- If launcher directory is not on `PATH`, N-VIEW prints exactly what to add.
