# MaldocTriage

A **static-only** triage tool for suspicious documents. It parses files and reports
suspicious indicators without ever executing macros, scripts, or embedded payloads.

MaldocTriage is a defensive / DFIR aid: it helps an analyst decide whether a document
is worth deeper investigation (sandbox, reverse engineering) by surfacing static
indicators and extracting indicators of compromise (IOCs).

## Supported formats

| Format | Detects |
| ------ | ------- |
| **OOXML** (`.docx`, `.docm`, `.xlsx`, `.xlsm`, `.pptx`, `.pptm`) | VBA macros, remote template injection, DDE, external/remote relationships, OLE objects |
| **Legacy OLE** (`.doc`, `.xls`, `.ppt`) | OLE compound file, VBA macro streams, embedded objects, Equation Editor objects |
| **PDF** | `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/URI`, encryption |
| **RTF** | `\objdata`, `\objupdate`, embedded OLE, Equation Editor, hex obfuscation |

Every file also gets an **IOC sweep** (URLs, IPv4 addresses, domains).

## Why static-only?

MaldocTriage never runs the document. It only reads and parses bytes. That makes it
safe to run on an analyst workstation and keeps it strictly a defensive tool.

## Install

```bash
pip install -e .
```

No third-party runtime dependencies — it uses only the Python standard library.

## Usage

```bash
# Triage one or more files
maldoc-triage suspicious.docm invoice.pdf

# Or run without installing
python -m maldoc_triage suspicious.docm

# JSON output (for pipelines)
maldoc-triage --json suspicious.docm

# Only show files at or above a risk level
maldoc-triage --min-severity high *.doc

# Scan a whole directory recursively
maldoc-triage --recursive ./samples
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | All scanned files are `clean` or `low` risk |
| `1` | At least one file scored `medium` risk |
| `2` | At least one file scored `high` / `critical` risk |
| `3` | Usage / IO error |

## Risk scoring

Each finding carries a severity (`info` → `critical`) with a weight. The file's total
score maps to a risk band:

| Score | Band |
| ----- | ---- |
| 0 | clean |
| 1–9 | low |
| 10–24 | medium |
| 25–49 | high |
| 50+ | critical |

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Disclaimer

MaldocTriage is a heuristic triage aid, not a verdict engine. A `clean` result does not
guarantee a file is safe, and findings are indicators, not proof of malice. Always
corroborate with additional analysis.
