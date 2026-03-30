# Configuration and Presets

N-VIEW configuration sources:

1. `.env` (preferred for keys)
2. Local config JSON in user profile

Environment source resolution order:

1. `~/.config/nview/.env`
2. `<repo>/.env`
3. `<current working directory>/.env`

Effective AI values are persisted to `~/.config/nview/config.json`, so keys/models remain available across directories until changed via `.env` or `configure-ai`.

Presets are available in interactive mode and natural-language normalization.

Runtime bootstrap settings:

- Use `python -m nview.cli bootstrap` to validate dependencies and configure launchers.
- Launchers are installed for both `nview` and `n-view`.
- Platform-aware dependency checks run through `doctor` and bootstrap routines.
