# Corpus scan results

Ran `python3 -m hashvault scan` from the repository root on 2026-11-20, 12:07:59–12:08:00 +05:30 (Asia/Calcutta, UTC+5:30). The clock zone is `Asia/Kolkata`, the IANA name for Asia/Calcutta.

Quarantine directory: `/tmp/hashvault-corpus-scans`. Every command passes `--registry corpus/registry.yaml`. `policies/known-good.yaml` is the default empty registry and was not used. `corpus/registry.yaml` was not edited: the clean full model's manifest `root_sha256` is `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`, and its file hashes are `config.json` `130815074e0b3c0c78d3300ac59b6311dcfd6f990a1ec3acdb0c9b62295db523` and `model.safetensors` `0b710ba164b9374e54d3176e09f7ad876991c0f4dac18c948f2e182eb7fd0aff`. Those are the same values already stored in the registry, and they are the values intake computed.

Exit 20 is Undetermined (no critical finding). Exit 30 is Blocked (a critical finding). `hashvault scan` does not exit 0; the behavioural inspector has not run.

`provenance_hash_match` on `clean/tiny-full-model` passed. The check matched registry row `acme/tiny-base`, compared 2 files, and recorded root `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`.

## Summary

| Artifact | Exit | Verdict | Expected check | Seen | Signal |
| --- | --- | --- | --- | --- | --- |
| `clean/tiny-full-model` | 20 | Undetermined | none | — | `provenance_hash_match` passed; `safetensors_structure` passed. Extra: `provenance_publisher` failed warning |
| `clean/tiny-lora` | 20 | Undetermined | none | — | `provenance_base_claim` passed; static safetensors checks passed. Extra: `provenance_config` failed warning |
| `suspicious/marker-pickle` | 30 | Blocked | `pickle_dangerous_callable` critical | yes, failed, critical | finding: `os.system` via GLOBAL at `model.pickle` |
| `suspicious/disguised-pickle` | 30 | Blocked | `intake.format_mismatch` warning; `pickle_dangerous_callable` critical | both yes | format mismatch failed warning; finding `os.system` at `model.safetensors` |
| `suspicious/trailing-bytes` | 30 | Blocked | `safetensors_trailing_bytes` critical | yes, failed, critical | 16 trailing bytes; `safetensors_structure` still passed |
| `suspicious/spoofed-base` | 20 | Undetermined | `provenance_base_claim` warning | yes, failed, warning | adapter claims `evil/not-the-base`; request claims `acme/tiny-base` |
| `suspicious/lookalike-name` | 20 | Undetermined | `provenance_typosquat` warning | yes, failed, warning | `acme/tiny-bose` vs `acme/tiny-base`, `token_sort_ratio` 92.86 |
| `suspicious/config-mismatch` | 30 | Blocked | `provenance_config` warning | absent | `provenance_config` skipped (`no_reference_config`); `provenance_hash_match` failed critical instead |
| `suspicious/hash-mismatch` | 30 | Blocked | `provenance_hash_match` critical | yes, failed, critical | root `4fc0bdc7a93602e5733147cacfcf402914546c774f524d6d5592e153dc28b139` vs registry `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815` |
| `suspicious/nested-torch-zip` | 30 | Blocked | `pickle_dangerous_callable` critical | yes, failed, critical | inner `model.bin!/archive/data.pkl` at depth 1, GLOBAL `os.system` |

## Commands and check ids

Check ids are every id the scan emitted (intake, static, and provenance). Severity is shown when the check carries one.

Passing `--base acme/tiny-base` selects registry row `acme/tiny-base` for a non-LoRA artifact. Samples that are not that registered tree then fail `provenance_hash_match` (critical) in addition to their labelled check. The registry publisher is `acme`. Commands that do not pass `--publisher` fail `provenance_publisher` at warning when that row is selected. Those extra findings are recorded under each artifact. They are not the labelled check.

### `clean/tiny-full-model` — exit 20

`python3 -m hashvault scan corpus/clean/tiny-full-model --base acme/tiny-base --repo acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

Artifact type `full_model`. Root hash equals the registry. `provenance_hash_match` passed.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` passed, `provenance_base_claim` not_applicable, `provenance_config` passed, `provenance_typosquat` passed, `provenance_publisher` failed warning, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `provenance_publisher` warning at `acme/tiny-base`. The registry publisher is `acme` and the command does not pass `--publisher`, so the claimed publisher is null. This is not a labelled check. Static safetensors checks passed, and the hash match passed.

### `clean/tiny-lora` — exit 20

`python3 -m hashvault scan corpus/clean/tiny-lora --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

Artifact type `lora_adapter`. `provenance_hash_match` skipped (`no_known_good_reference`): a LoRA is not compared to the base model's hash. `provenance_base_claim` passed (`base_model_name_or_path` and `--base` are both `acme/tiny-base`).

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` skipped, `provenance_base_claim` passed, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `provenance_config` warning. `--base acme/tiny-base` selects the registry config (`model_type` tiny, `architectures` `[TinyForCausalLM]`, `hidden_size` 8, `num_hidden_layers` 2, `vocab_size` 32). The adapter has no `config.json`, so those claims are absent and the check treats every field as a diff. The labelled expectation is no suspicious check. The base-claim check passed.

### `suspicious/marker-pickle` — exit 30

`python3 -m hashvault scan corpus/suspicious/marker-pickle --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` failed warning, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `pickle_dangerous_callable` critical at `model.pickle` (`os.system`, opcode GLOBAL). Also `provenance_hash_match` critical, because `--base acme/tiny-base` selects the registry row and this tree is not that model (root and both registered files differ). `provenance_config` warning because there is no config. `provenance_publisher` warning because no `--publisher` was passed.

### `suspicious/disguised-pickle` — exit 30

`python3 -m hashvault scan corpus/suspicious/disguised-pickle --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` failed warning, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` failed warning, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `pickle_dangerous_callable` critical at `model.safetensors` (`os.system`, opcode GLOBAL). Detected format of that file is `pickle`; the extension format is `safetensors`, so `intake.format_mismatch` failed warning. Also `provenance_hash_match` critical (`--base` selects `acme/tiny-base`), `provenance_config` warning, and `provenance_publisher` warning.

### `suspicious/trailing-bytes` — exit 30

`python3 -m hashvault scan corpus/suspicious/trailing-bytes --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` failed critical, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` passed, `provenance_typosquat` passed, `provenance_publisher` failed warning, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `safetensors_trailing_bytes` critical at `model.safetensors` (16 trailing bytes after the last tensor). `provenance_config` passed (`hidden_size` is still 8). `provenance_hash_match` failed critical on the root and on `model.safetensors`, because the appended bytes change those hashes. `provenance_publisher` failed warning.

### `suspicious/spoofed-base` — exit 20

`python3 -m hashvault scan corpus/suspicious/spoofed-base --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` skipped, `provenance_base_claim` failed warning, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `provenance_base_claim` warning at `adapter_config.json`. The adapter's `base_model_name_or_path` is `evil/not-the-base` and the request's `--base` is `acme/tiny-base`. `provenance_hash_match` skipped because this is a LoRA. `provenance_config` also failed warning, for the same reason as the clean LoRA: the adapter has no `config.json` fields to compare with the base registry config. Static safetensors checks passed. Exit stays 20 because both provenance findings are warnings.

### `suspicious/lookalike-name` — exit 20

`python3 -m hashvault scan corpus/suspicious/lookalike-name --repo acme/tiny-bose --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` skipped, `provenance_base_claim` not_applicable, `provenance_config` skipped, `provenance_typosquat` failed warning, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `provenance_typosquat` warning. Claimed repo `acme/tiny-bose` against trusted name `acme/tiny-base` scored 92.86 by `token_sort_ratio` (threshold 90). It is not an exact trusted name. `provenance_hash_match` skipped because `acme/tiny-bose` is not a registry row and this command does not pass `--base`. `provenance_config` skipped (`no_reference_config`). Entries: `config.json`, `model.safetensors`, `scan.yaml`.

The sidecar is the same request. `python3 -m hashvault scan --request corpus/suspicious/lookalike-name/scan.yaml --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans` also exited 20, with the same `provenance_typosquat` failure (score 92.86, `token_sort_ratio`, `acme/tiny-bose` vs `acme/tiny-base`).

### `suspicious/config-mismatch` — exit 30

`python3 -m hashvault scan corpus/suspicious/config-mismatch --repo acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

The labelled check did not appear. `provenance_config` is skipped with reason `no_reference_config`. Its details are `claimed_base_model: null` and `matched: null`. The config check reads the registry row for `--base` (`claimed_base_model`). This command, which is the command in `corpus/README.md`, passes `--repo acme/tiny-base` and does not pass `--base`.

What fired instead is `provenance_hash_match`, failed, critical. `--repo acme/tiny-base` does select registry row `acme/tiny-base` for the hash check. The artifact `config.json` has `hidden_size` 999, so its file hash is `31cda24a31502b1b37ab0398dc8d9cb00885dba30f7f3f9a0bc554c0376239eb` against the registry file hash `130815074e0b3c0c78d3300ac59b6311dcfd6f990a1ec3acdb0c9b62295db523`. The root hash is `eb0966624333e829c7facc3399837d9ea0de1be7d7686f968fc273228d11e45b` against registry root `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`. `model.safetensors` still matches the registry, so it is not a mismatch. `provenance_publisher` also failed warning because the selected row's publisher is `acme` and no `--publisher` was passed. The hash finding is critical, so the exit is 30 rather than the warning-level 20 the `provenance_config` label describes.

The claims on this artifact do contain `hidden_size` 999. The config comparison did not run, because there is no claimed base. A separate invocation that adds `--base acme/tiny-base` to the labelled command fails `provenance_config` on `hidden_size` (actual 999, registry 8) and still fails `provenance_hash_match` critical, so that exit is also 30. That extra flag is not the command in the README, and it is not the result in the table above.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` skipped, `provenance_typosquat` passed, `provenance_publisher` failed warning, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

### `suspicious/hash-mismatch` — exit 30

`python3 -m hashvault scan --request corpus/suspicious/hash-mismatch/scan.yaml --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` skipped, `provenance_typosquat` passed, `provenance_publisher` failed warning, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `provenance_hash_match` critical at `<root>`. The request sets `claimed_repo` to `acme/tiny-base`. Manifest root `4fc0bdc7a93602e5733147cacfcf402914546c774f524d6d5592e153dc28b139` differs from registry root `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`. `config.json` and `model.safetensors` match the registry file hashes, so the only mismatch is the root. `README.txt` (the word `extra`) and `scan.yaml` are the extra entries that move the root. `provenance_config` skipped because the request has no claimed base. `provenance_publisher` failed warning. Entries: `README.txt`, `config.json`, `model.safetensors`, `scan.yaml`.

### `suspicious/nested-torch-zip` — exit 30

`python3 -m hashvault scan corpus/suspicious/nested-torch-zip --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` passed, `intake.archive_member_rejected` passed, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `weight_coverage` passed (`model.bin`, detected format `torch_zip`, inner pickle `model.bin!/archive/data.pkl`), `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` failed warning, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `pickle_dangerous_callable` critical at `model.bin!/archive/data.pkl` (`os.system`, opcode GLOBAL). That member is depth 1. `model.bin` itself is depth 0, format `torch_zip`. Also `provenance_hash_match` critical (`--base` selects `acme/tiny-base`), `provenance_config` warning (no config), and `provenance_publisher` warning.
