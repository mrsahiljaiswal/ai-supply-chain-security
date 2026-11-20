# Corpus scan results

Ran `python3 -m hashvault scan` from the repository root on 2026-11-20, 11:56:31–11:56:33 +05:30 (Asia/Calcutta, UTC+5:30). The clock zone is `Asia/Kolkata`, the IANA name for Asia/Calcutta.

Quarantine directory: `/tmp/hashvault-corpus-scans`. The documented `--registry corpus/registry.yaml` flag is absent from this CLI (`No such option: --registry`, exit 2). The commands below omit it. `scan --help` states that provenance and behavioural are not run.

The clean full model's manifest `root_sha256` is `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`, the same value as `registry.yaml`.

Exit 20 is Undetermined (no critical static finding). Exit 30 is Blocked (a critical static finding).

## Summary

| Artifact | Exit | Verdict | Expected check | Seen | Signal |
| --- | --- | --- | --- | --- | --- |
| `clean/tiny-full-model` | 20 | Undetermined | none | — | `safetensors_structure` passed, `safetensors_trailing_bytes` passed |
| `clean/tiny-lora` | 20 | Undetermined | none | — | `safetensors_structure` passed, `safetensors_trailing_bytes` passed |
| `suspicious/marker-pickle` | 30 | Blocked | `pickle_dangerous_callable` critical | yes, failed, critical | finding: `os.system` via GLOBAL at `model.pickle` |
| `suspicious/disguised-pickle` | 30 | Blocked | `intake.format_mismatch` warning; `pickle_dangerous_callable` critical | both yes | format mismatch failed warning; finding `os.system` at `model.safetensors` |
| `suspicious/trailing-bytes` | 30 | Blocked | `safetensors_trailing_bytes` critical | yes, failed, critical | 16 trailing bytes; `safetensors_structure` still passed |
| `suspicious/spoofed-base` | 20 | Undetermined | `provenance_base_claim` warning | absent | provenance inspector not merged; static safetensors checks passed |
| `suspicious/lookalike-name` | 20 | Undetermined | `provenance_typosquat` warning | absent | provenance inspector not merged; static safetensors checks passed |
| `suspicious/config-mismatch` | 20 | Undetermined | `provenance_config` warning | absent | provenance inspector not merged; static safetensors checks passed |
| `suspicious/hash-mismatch` | 20 | Undetermined | `provenance_hash_match` critical | absent | provenance inspector not merged; root hash differs from the registry |
| `suspicious/nested-torch-zip` | 30 | Blocked | `pickle_dangerous_callable` critical | yes, failed, critical | inner `model.bin!/archive/data.pkl` at depth 1, GLOBAL `os.system` |

## Commands and check ids

Check ids are every id the scan emitted (intake plus static). Severity is shown when the check carries one.

### `clean/tiny-full-model` — exit 20

`python3 -m hashvault scan corpus/clean/tiny-full-model --base acme/tiny-base --repo acme/tiny-base --work-dir /tmp/hashvault-corpus-scans`

Artifact type `full_model`. Root hash matches the registry.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed.

Findings: none.

### `clean/tiny-lora` — exit 20

`python3 -m hashvault scan corpus/clean/tiny-lora --base acme/tiny-base --work-dir /tmp/hashvault-corpus-scans`

Artifact type `lora_adapter`.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed.

Findings: none.

### `suspicious/marker-pickle` — exit 30

`python3 -m hashvault scan corpus/suspicious/marker-pickle --base acme/tiny-base --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed.

Finding: `pickle_dangerous_callable` critical at `model.pickle` (`os.system`, opcode GLOBAL).

### `suspicious/disguised-pickle` — exit 30

`python3 -m hashvault scan corpus/suspicious/disguised-pickle --base acme/tiny-base --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` failed warning, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed.

Finding: `pickle_dangerous_callable` critical at `model.safetensors` (`os.system`, opcode GLOBAL). Detected format of that file is `pickle`.

### `suspicious/trailing-bytes` — exit 30

`python3 -m hashvault scan corpus/suspicious/trailing-bytes --base acme/tiny-base --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` failed critical, `custom_code_present` passed.

Finding: `safetensors_trailing_bytes` critical at `model.safetensors` (16 trailing bytes, the ASCII string `HASHVAULT_MARKER`).

### `suspicious/spoofed-base` — exit 20

`python3 -m hashvault scan corpus/suspicious/spoofed-base --base acme/tiny-base --work-dir /tmp/hashvault-corpus-scans`

`provenance_base_claim` did not appear. This build has no provenance inspector. Static checks passed, so the interim gate stays Undetermined.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed.

Findings: none. Artifact type `lora_adapter`.

### `suspicious/lookalike-name` — exit 20

`python3 -m hashvault scan corpus/suspicious/lookalike-name --repo acme/tiny-bose --work-dir /tmp/hashvault-corpus-scans`

`provenance_typosquat` did not appear. This build has no provenance inspector. The sidecar `scan.yaml` validates as a `ScanRequest` with `claimed_repo: acme/tiny-bose`.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed.

Findings: none. Entries: `config.json`, `model.safetensors`, `scan.yaml`.

### `suspicious/config-mismatch` — exit 20

`python3 -m hashvault scan corpus/suspicious/config-mismatch --repo acme/tiny-base --work-dir /tmp/hashvault-corpus-scans`

`provenance_config` did not appear. This build has no provenance inspector. `config.json` in the artifact has `hidden_size` 999; the registry says 8.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed.

Findings: none.

### `suspicious/hash-mismatch` — exit 20

`python3 -m hashvault scan --request corpus/suspicious/hash-mismatch/scan.yaml --work-dir /tmp/hashvault-corpus-scans`

`provenance_hash_match` did not appear. This build has no provenance inspector. The request file set `claimed_repo` to `acme/tiny-base`. Manifest root hash `4fc0bdc7a93602e5733147cacfcf402914546c774f524d6d5592e153dc28b139` differs from the registry root `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed.

Findings: none. Entries: `README.txt`, `config.json`, `model.safetensors`, `scan.yaml`.

### `suspicious/nested-torch-zip` — exit 30

`python3 -m hashvault scan corpus/suspicious/nested-torch-zip --base acme/tiny-base --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` passed, `intake.archive_member_rejected` passed, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `weight_coverage` passed (`model.bin`), `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed.

Finding: `pickle_dangerous_callable` critical at `model.bin!/archive/data.pkl` (`os.system`, opcode GLOBAL). That member is depth 1. `model.bin` itself is depth 0, format `torch_zip`.
