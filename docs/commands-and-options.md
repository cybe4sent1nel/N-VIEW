# Commands and Options

- `menu`: guided numbered flow
- `scan`: direct execution
- `configure-ai`: set provider/models/keys
- `doctor`: platform and dependency diagnostics
- `bootstrap`: dependency remediation + launcher setup
- `history`: review recent scan artifacts and report availability
- `analyze`: run visual intelligence analytics on existing XML outputs
- `report`: render saved AI report markdown with rich formatting in terminal
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
python -m nview.cli history --limit 20
python -m nview.cli analyze --xml ./nview-results/target_20260329_120000.xml
python -m nview.cli report --latest
```

Advanced scan examples:

```bash
python -m nview.cli scan --target 10.10.10.10 --nl "quick scan" --timing 4 --top-ports 500 --scripts default,safe --retries 2
python -m nview.cli scan --target-file targets.txt --flags "-sV -Pn" --udp --os-detect --no-ai
```
