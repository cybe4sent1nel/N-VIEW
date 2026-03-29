# Commands and Options

- `menu`: guided numbered flow
- `scan`: direct execution
- `configure-ai`: set provider/models/keys
- `doctor`: platform and dependency diagnostics
- `bootstrap`: dependency remediation + launcher setup
- `version`: show version and branding

Run help:

```bash
python -m nview.cli --help
```

Common production commands:

```bash
python -m nview.cli bootstrap
python -m nview.cli doctor
python -m nview.cli menu
python -m nview.cli scan --target 127.0.0.1 --nl "quick service scan"
```
