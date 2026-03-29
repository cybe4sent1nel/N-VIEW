# Quick Usage and Examples

Bootstrap first:

```bash
python -m nview.cli bootstrap
```

Interactive mode:

```bash
nview
```

Direct scan mode:

```bash
n-view scan --target scanme.nmap.org --nl "quick service scan"
```

Advanced tuning example:

```bash
nview scan --target 127.0.0.1 --flags "-sV" --top-ports 1000 --timing 4 --scripts default,safe --retries 2
```

Scan from target file:

```bash
nview scan --target-file targets.txt --flags "-sV -Pn" --udp --os-detect --no-ai
```

Review history:

```bash
nview history --limit 25
```

History now includes risk level and open-port counts per scan for faster triage.

Analyze an existing XML with visual intelligence:

```bash
nview analyze --xml ./nview-results/target_YYYYMMDD_HHMMSS.xml
```

Health check:

```bash
python -m nview.cli doctor
```
