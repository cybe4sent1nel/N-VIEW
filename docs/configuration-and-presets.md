# Configuration and Presets

N-VIEW configuration sources:

1. `.env` (preferred for keys)
2. Local config JSON in user profile

Presets are available in interactive mode and natural-language normalization.

Runtime bootstrap settings:

- Use `python -m nview.cli bootstrap` to validate dependencies and configure launchers.
- Launchers are installed for both `nview` and `n-view`.
- Platform-aware dependency checks run through `doctor` and bootstrap routines.
