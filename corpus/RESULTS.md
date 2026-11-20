# Corpus scan results

Ran `python3 -m hashvault scan` from the repository root on 2026-11-20, 12:25:01–12:25:03 +05:30 (Asia/Calcutta, UTC+5:30). The clock zone is `Asia/Kolkata`, the IANA name for Asia/Calcutta.

Quarantine directory: `/tmp/hashvault-corpus-scans`. Every command passes `--registry corpus/registry.yaml`. `policies/known-good.yaml` is the default empty registry and was not used. `corpus/registry.yaml` was not edited: the clean full model's manifest `root_sha256` is `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`, and its file hashes are `config.json` `130815074e0b3c0c78d3300ac59b6311dcfd6f990a1ec3acdb0c9b62295db523` and `model.safetensors` `0b710ba164b9374e54d3176e09f7ad876991c0f4dac18c948f2e182eb7fd0aff`. Those are the same values already stored in the registry, and they are the values intake computed.

Exit 0 is Trusted. Exit 10 is Conditional (a warning, and no critical finding). Exit 20 is Undetermined. Exit 30 is Blocked (a critical finding). The behavioural inspector has not run, so a scan with no critical finding and no warning is Undetermined (`rule_insufficient_evidence`) and does not exit 0. A warning is `rule_warnings` and exits 10. Each command also passed `--out` pointing at a temp directory; that flag only places the JSON bundle and does not change the checks.

Behavioural eligibility fails closed on this corpus. The registry rows have no `local_path`, and these commands do not pass `--base-dir`, so the reason is `base_weights_missing` (or the model is not executed because a static critical finding or a non-safetensors weight blocks the load). These fixtures are not runnable language models, and they are not behaviourally clean. A skipped behavioural report is not coverage. The exit codes below stay as recorded. Nothing here is Trusted.

`provenance_hash_match` on `clean/tiny-full-model` passed. The check matched registry row `acme/tiny-base`, compared 2 files, and recorded root `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`. No `--publisher` was passed, so `provenance_publisher` is skipped (`publisher_not_claimed`) and there is no publisher warning.

## Summary

| Artifact | Exit | Verdict | Rule | Expected check | Seen | Signal |
| --- | --- | --- | --- | --- | --- | --- |
| `clean/tiny-full-model` | 20 | Undetermined | `rule_insufficient_evidence` | none | — | `provenance_hash_match` passed; `safetensors_structure` passed. No publisher warning |
| `clean/tiny-lora` | 20 | Undetermined | `rule_insufficient_evidence` | none | — | `provenance_base_claim` passed; `provenance_config` not_applicable. No config warning |
| `suspicious/marker-pickle` | 30 | Blocked | `rule_critical` | `pickle_dangerous_callable` critical | yes, failed, critical | finding: `os.system` via GLOBAL at `model.pickle` |
| `suspicious/disguised-pickle` | 30 | Blocked | `rule_critical` | `intake.format_mismatch` warning; `pickle_dangerous_callable` critical | both yes | format mismatch failed warning; finding `os.system` at `model.safetensors` |
| `suspicious/trailing-bytes` | 30 | Blocked | `rule_critical` | `safetensors_trailing_bytes` critical | yes, failed, critical | 16 trailing bytes; `safetensors_structure` still passed |
| `suspicious/spoofed-base` | 10 | Conditional | `rule_warnings` | `provenance_base_claim` warning | yes, failed, warning | adapter claims `evil/not-the-base`; request claims `acme/tiny-base` |
| `suspicious/lookalike-name` | 10 | Conditional | `rule_warnings` | `provenance_typosquat` warning | yes, failed, warning | `acme/tiny-bose` vs `acme/tiny-base`, `token_sort_ratio` 92.86 |
| `suspicious/config-mismatch` | 30 | Blocked | `rule_critical` | `provenance_config` warning | yes, failed, warning | `hidden_size` 999 vs registry 8. Also `provenance_hash_match` failed critical |
| `suspicious/hash-mismatch` | 30 | Blocked | `rule_critical` | `provenance_hash_match` critical | yes, failed, critical | root `4fc0bdc7a93602e5733147cacfcf402914546c774f524d6d5592e153dc28b139` vs registry `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815` |
| `suspicious/nested-torch-zip` | 30 | Blocked | `rule_critical` | `pickle_dangerous_callable` critical | yes, failed, critical | inner `model.bin!/archive/data.pkl` at depth 1, GLOBAL `os.system` |

## Commands and check ids

Check ids are every id the scan emitted (intake, static, and provenance). Severity is shown when the check carries one.

Passing `--base acme/tiny-base` selects registry row `acme/tiny-base` for a non-LoRA artifact. Samples that are not that registered tree then fail `provenance_hash_match` (critical) in addition to their labelled check. Commands that do not pass `--publisher` skip `provenance_publisher` with reason `publisher_not_claimed`. That skip is not a warning. A full model whose claimed base selects the registry config, and whose own config claims are missing, still fails `provenance_config` at warning. A LoRA does not: `provenance_config` is `not_applicable` (`adapter_has_no_model_config`).

### `clean/tiny-full-model` — exit 20

`python3 -m hashvault scan corpus/clean/tiny-full-model --base acme/tiny-base --repo acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

Artifact type `full_model`. Root hash equals the registry. `provenance_hash_match` passed. Rule `rule_insufficient_evidence`: the behavioural inspector has not run. There is no warning, so the exit is 20 rather than 10.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` passed, `provenance_base_claim` not_applicable, `provenance_config` passed, `provenance_typosquat` passed, `provenance_publisher` skipped (`publisher_not_claimed`), `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

No findings. Static safetensors checks passed, the hash match passed, and the omitted publisher is not a warning.

### `clean/tiny-lora` — exit 20

`python3 -m hashvault scan corpus/clean/tiny-lora --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

Artifact type `lora_adapter`. `provenance_hash_match` skipped (`no_known_good_reference`): a LoRA is not compared to the base model's hash. `provenance_base_claim` passed (`base_model_name_or_path` and `--base` are both `acme/tiny-base`). `provenance_config` is not_applicable (`adapter_has_no_model_config`). The adapter has no `hidden_size`, and that is not a config warning. Rule `rule_insufficient_evidence`.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` skipped, `provenance_base_claim` passed, `provenance_config` not_applicable, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

No findings. The base-claim check passed. Static safetensors checks passed.

### `suspicious/marker-pickle` — exit 30

`python3 -m hashvault scan corpus/suspicious/marker-pickle --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `pickle_dangerous_callable` critical at `model.pickle` (`os.system`, opcode GLOBAL). Also `provenance_hash_match` critical, because `--base acme/tiny-base` selects the registry row and this tree is not that model (root and both registered files differ). The artifact is classified `full_model` (it has a weight file and no config), so `provenance_config` warns that the registry config fields are absent. `provenance_publisher` skipped (`publisher_not_claimed`). The critical findings decide the verdict.

### `suspicious/disguised-pickle` — exit 30

`python3 -m hashvault scan corpus/suspicious/disguised-pickle --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` failed warning, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `pickle_dangerous_callable` critical at `model.safetensors` (`os.system`, opcode GLOBAL). Detected format of that file is `pickle`; the extension format is `safetensors`, so `intake.format_mismatch` failed warning. Also `provenance_hash_match` critical (`--base` selects `acme/tiny-base`) and `provenance_config` warning (no config claims). `provenance_publisher` skipped. The critical findings decide the verdict.

### `suspicious/trailing-bytes` — exit 30

`python3 -m hashvault scan corpus/suspicious/trailing-bytes --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` failed critical, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` passed, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `safetensors_trailing_bytes` critical at `model.safetensors` (16 trailing bytes after the last tensor). `provenance_config` passed (`hidden_size` is still 8). `provenance_hash_match` failed critical on the root (`3e0efd0e62e12eef02b0a8b77b474072cf51699a3a6cc4682eff74689c91a495`) and on `model.safetensors`, because the appended bytes change those hashes. `provenance_publisher` skipped.

### `suspicious/spoofed-base` — exit 10

`python3 -m hashvault scan corpus/suspicious/spoofed-base --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` skipped, `provenance_base_claim` failed warning, `provenance_config` not_applicable, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `provenance_base_claim` warning at `adapter_config.json`. The adapter's `base_model_name_or_path` is `evil/not-the-base` and the request's `--base` is `acme/tiny-base`. `provenance_hash_match` skipped because this is a LoRA. `provenance_config` is not_applicable (`adapter_has_no_model_config`), so the missing model config is not a second warning. Static safetensors checks passed. Rule `rule_warnings`, exit 10.

### `suspicious/lookalike-name` — exit 10

`python3 -m hashvault scan corpus/suspicious/lookalike-name --repo acme/tiny-bose --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` skipped, `provenance_base_claim` not_applicable, `provenance_config` skipped, `provenance_typosquat` failed warning, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `provenance_typosquat` warning. Claimed repo `acme/tiny-bose` against trusted name `acme/tiny-base` scored 92.86 by `token_sort_ratio` (threshold 90). It is not an exact trusted name. `provenance_hash_match` skipped because `acme/tiny-bose` is not a registry row and this command does not pass `--base`. `provenance_config` skipped (`no_reference_config`). Entries: `config.json`, `model.safetensors`, `scan.yaml`. Rule `rule_warnings`, exit 10.

The sidecar is the same request. `python3 -m hashvault scan --request corpus/suspicious/lookalike-name/scan.yaml --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans` also exited 10, with the same `provenance_typosquat` failure (score 92.86, `token_sort_ratio`, `acme/tiny-bose` vs `acme/tiny-base`) and rule `rule_warnings`.

### `suspicious/config-mismatch` — exit 30

`python3 -m hashvault scan corpus/suspicious/config-mismatch --base acme/tiny-base --repo acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

Both labelled and hash findings are present. `--base acme/tiny-base` selects the registry config, so `provenance_config` runs. It failed, warning, on `hidden_size`: actual 999, registry 8, at `config.json`. The other compared fields match.

`provenance_hash_match` also failed, critical. The artifact `config.json` hash is `31cda24a31502b1b37ab0398dc8d9cb00885dba30f7f3f9a0bc554c0376239eb` against the registry file hash `130815074e0b3c0c78d3300ac59b6311dcfd6f990a1ec3acdb0c9b62295db523`. The root hash is `eb0966624333e829c7facc3399837d9ea0de1be7d7686f968fc273228d11e45b` against registry root `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`. `model.safetensors` still matches the registry. The registry hashes were not changed. The critical hash finding decides the verdict (`rule_critical`, exit 30). The config warning remains on the bundle.

`provenance_publisher` skipped (`publisher_not_claimed`). `provenance_base_claim` not_applicable because this full model has no adapter base claim.

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

### `suspicious/hash-mismatch` — exit 30

`python3 -m hashvault scan --request corpus/suspicious/hash-mismatch/scan.yaml --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` not_applicable, `intake.archive_member_rejected` not_applicable, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` passed, `safetensors_structure` passed, `safetensors_trailing_bytes` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` skipped, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `provenance_hash_match` critical at `<root>`. The request sets `claimed_repo` to `acme/tiny-base`. Manifest root `4fc0bdc7a93602e5733147cacfcf402914546c774f524d6d5592e153dc28b139` differs from registry root `4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`. `config.json` and `model.safetensors` match the registry file hashes, so the only mismatch is the root. `README.txt` (the word `extra`) and `scan.yaml` are the extra entries that move the root. `provenance_config` skipped because the request has no claimed base. `provenance_publisher` skipped (`publisher_not_claimed`). Entries: `README.txt`, `config.json`, `model.safetensors`, `scan.yaml`.

### `suspicious/nested-torch-zip` — exit 30

`python3 -m hashvault scan corpus/suspicious/nested-torch-zip --base acme/tiny-base --registry corpus/registry.yaml --work-dir /tmp/hashvault-corpus-scans`

`intake.stage` passed, `intake.limits` passed, `intake.inventory` passed, `intake.archive_expansion` passed, `intake.archive_member_rejected` passed, `intake.special_files` passed, `intake.format_mismatch` passed, `intake.unsupported_format` passed, `intake.unknown_format` passed, `intake.type_mismatch` not_applicable, `intake.claims` not_applicable, `weight_coverage` passed (`model.bin`, detected format `torch_zip`, inner pickle `model.bin!/archive/data.pkl`), `pickle_opcode_scan` passed, `pickle_dangerous_callable` failed critical, `pickle_unknown_global` passed, `custom_code_present` passed, `provenance_hash_match` failed critical, `provenance_base_claim` not_applicable, `provenance_config` failed warning, `provenance_typosquat` passed, `provenance_publisher` skipped, `provenance_hub_metadata` skipped, `provenance_attestation` skipped.

Finding: `pickle_dangerous_callable` critical at `model.bin!/archive/data.pkl` (`os.system`, opcode GLOBAL). That member is depth 1. `model.bin` itself is depth 0, format `torch_zip`. Also `provenance_hash_match` critical (`--base` selects `acme/tiny-base`) and `provenance_config` warning (classified `full_model`, no config claims). `provenance_publisher` skipped. The critical findings decide the verdict.
