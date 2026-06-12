# isis-lsdb-parser

Custom Python parser for `show isis lsdb detail` output on Extreme Networks
VSP (SPBM fabric) devices.

## Why not TextFSM

TextFSM is line-oriented: one input line maps to one output field. The ISIS
LSDB detail output contains deeply nested TLV/sub-TLV structures (multiple
ISIDs per sub-TLV, multiple sub-TLVs per LSP fragment, multiple fragments per
node) that TextFSM cannot model without unmaintainable post-processing. This
module is a purpose-built recursive descent / state-machine parser instead.

## Usage

```bash
python3 isis_lsdb_parser.py <input_file> [output_dir]
```

Produces two output formats:
- **Flat** (`lsp_flat.csv`): one row per LSP fragment, multi-value fields
  JSON-encoded. Good for spreadsheet review.
- **Normalized** (six CSVs): `lsp_summary`, `lsp_adjacencies`, `lsp_prefixes`,
  `lsp_isids`, `lsp_spbm_instance`, `lsp_multicast` -- one row per atomic
  entity, suitable for SQLite/pandas.

## Status

Parser validated against two SPBM fabric corpora (107-319 LSP fragments).
Tests and CI pipeline in progress.

## Requirements

- Python 3.10+
- `pytest` (dev only -- see `requirements.txt`)
