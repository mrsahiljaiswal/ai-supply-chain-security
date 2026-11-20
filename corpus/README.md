# HashVault labelled corpus

Fixtures for the defensive HashVault scanner. A suspicious sample is a detectable marker: opcode bytes that name a callable, an ASCII marker string, or a config/hash claim the registry can disagree with. Pickle streams in this tree are built as opcode bytes. Nothing in the corpus calls `pickle.load` or `torch.load`.

`os.system` is the GLOBAL named in the pickle fixtures. `hashvault/inspectors/static/rules.py` denies the whole `os` module, so the static scanner reports `pickle_dangerous_callable`. The deny list has no `hashvault_marker` entry, so that module name would come back as an unknown global.

`spoofed-base` is a spoofed-lineage fixture: a tiny valid safetensors adapter whose config names `evil/not-the-base`. Real trigger-behaviour fixtures wait for the behavioural inspector.

Labels and expected checks are in `manifest.csv`. The known-good registry is `registry.yaml`. Scan results from this tree are in `RESULTS.md`.

## Registry and root hash

`registry.yaml` describes `acme/tiny-base`, the clean full model in `clean/tiny-full-model`.

- Each file hash is SHA-256 of the file bytes, streamed in 1 MiB chunks.
- The root hash is SHA-256 over the sorted lines `relative/path:file_sha256`, each line ending in a newline. That is the function in `hashvault/intake/hashing.py`.
- Paths are relative to the artifact directory: `config.json` and `model.safetensors`.
- An expanded archive member is spelled `outer.zip!/inner/path`. This corpus keeps the registered model flat so the root hash is only those two files.

Registered root hash of `clean/tiny-full-model`:

`4af949ba6e98a9622faab99debc5159655c830777b9e709d04859e28fc356815`

`trusted_names` lists `acme/tiny-base` and `acme/tiny-adapter`.

## How to run

From the repository root:

```bash
python3 -m hashvault scan corpus/<name> --base <id> --registry corpus/registry.yaml
```

`--base` is the claimed base model. Intake requires it when the artifact is a LoRA adapter. `--registry corpus/registry.yaml` is the provenance registry. On a CLI that has not grown `--registry` yet, run the same command without that flag; the file stays the contract for the inspector. Add `--work-dir` to keep quarantine copies out of the tree (the default is `./work`).

`hashvault scan` runs intake, the static scanner, the provenance inspector, and the verdict engine. Exit 0 is Trusted, 10 is Conditional, 20 is Undetermined, and 30 is Blocked. The behavioural inspector does not run, so a scan with no critical finding and no warning is Undetermined. A warning with no critical finding is Conditional. A critical finding is Blocked.

`scan.yaml` files are `ScanRequest` documents. Run one with `--request`. Paths inside them are relative to the repository root. The file also sits inside the artifact directory, so it is part of that artifact's inventory and root hash.

| Artifact | Command |
| --- | --- |
| `clean/tiny-full-model` | `python3 -m hashvault scan corpus/clean/tiny-full-model --base acme/tiny-base --repo acme/tiny-base --registry corpus/registry.yaml` |
| `clean/tiny-lora` | `python3 -m hashvault scan corpus/clean/tiny-lora --base acme/tiny-base --registry corpus/registry.yaml` |
| `suspicious/marker-pickle` | `python3 -m hashvault scan corpus/suspicious/marker-pickle --base acme/tiny-base --registry corpus/registry.yaml` |
| `suspicious/disguised-pickle` | `python3 -m hashvault scan corpus/suspicious/disguised-pickle --base acme/tiny-base --registry corpus/registry.yaml` |
| `suspicious/trailing-bytes` | `python3 -m hashvault scan corpus/suspicious/trailing-bytes --base acme/tiny-base --registry corpus/registry.yaml` |
| `suspicious/spoofed-base` | `python3 -m hashvault scan corpus/suspicious/spoofed-base --base acme/tiny-base --registry corpus/registry.yaml` |
| `suspicious/lookalike-name` | `python3 -m hashvault scan corpus/suspicious/lookalike-name --repo acme/tiny-bose --registry corpus/registry.yaml` |
| `suspicious/config-mismatch` | `python3 -m hashvault scan corpus/suspicious/config-mismatch --base acme/tiny-base --repo acme/tiny-base --registry corpus/registry.yaml` |
| `suspicious/hash-mismatch` | `python3 -m hashvault scan --request corpus/suspicious/hash-mismatch/scan.yaml --registry corpus/registry.yaml` |
| `suspicious/nested-torch-zip` | `python3 -m hashvault scan corpus/suspicious/nested-torch-zip --base acme/tiny-base --registry corpus/registry.yaml` |

The lookalike sidecar is the same request: `python3 -m hashvault scan --request corpus/suspicious/lookalike-name/scan.yaml --registry corpus/registry.yaml`.

## Clean

### `clean/tiny-full-model`

`config.json` is `model_type` `tiny`, `architectures` `[TinyForCausalLM]`, `hidden_size` 8, `num_hidden_layers` 2, `vocab_size` 32. `model.safetensors` is one float32 tensor named `weight` with shape `[8]`. The header is an 8-byte little-endian length, JSON padded to a multiple of 8, then exactly the tensor bytes.

This directory is the registry entry `acme/tiny-base`. Static safetensors checks should pass.

### `clean/tiny-lora`

`adapter_config.json` sets `base_model_name_or_path` to `acme/tiny-base`, `r` to 4, and `target_modules` to `["q_proj"]`. `adapter_model.safetensors` holds two small float32 LoRA tensors (`lora_A` is `[4, 8]`, `lora_B` is `[8, 4]`). Scan with `--base acme/tiny-base`.

## Suspicious

### `suspicious/marker-pickle`

`model.pickle` is a protocol-2 stream: PROTO, GLOBAL `os.system`, STOP. The GLOBAL names the callable and STOP ends the stream. Expected check `pickle_dangerous_callable`, severity critical.

### `suspicious/disguised-pickle`

The same pickle bytes, saved as `model.safetensors`. Magic is pickle and the extension is safetensors, so intake reports `intake.format_mismatch` at warning. The static scanner still reports `pickle_dangerous_callable` at critical.

### `suspicious/trailing-bytes`

The clean full model, with the ASCII bytes `HASHVAULT_MARKER` appended to `model.safetensors` and no other extra bytes. The header still parses. Expected check `safetensors_trailing_bytes`, severity critical.

### `suspicious/spoofed-base`

The clean LoRA weights. `adapter_config.json` sets `base_model_name_or_path` to `evil/not-the-base`. Expected check `provenance_base_claim`, severity warning, once the provenance inspector is merged. Scan with `--base acme/tiny-base`.

### `suspicious/lookalike-name`

The clean full-model files, plus `scan.yaml` claiming `claimed_repo: acme/tiny-bose` (`tiny-bose` is one character off `tiny-base`). Expected check `provenance_typosquat`, severity warning. The claim is the `--repo` flag and the sidecar. Pass `--repo acme/tiny-bose`, or pass `--request` pointing at the sidecar.

### `suspicious/config-mismatch`

The clean weights. `config.json` sets `hidden_size` to 999. The registry config for `acme/tiny-base` says 8. Expected check `provenance_config`, severity warning. Scan with `--base acme/tiny-base` and `--repo acme/tiny-base`. `--base` selects the registry config so the `hidden_size` comparison runs. The config file hash, and therefore the root hash, also differs from the registry because the JSON bytes changed, so `provenance_hash_match` is critical as well. That hash result is kept.

### `suspicious/hash-mismatch`

The clean full model, plus `README.txt` containing the word `extra`, plus `scan.yaml` claiming `claimed_repo: acme/tiny-base`. Those extra files change the root hash away from the registry entry. Expected check `provenance_hash_match`, severity critical.

### `suspicious/nested-torch-zip`

`model.bin` is a stored zip whose only member is `archive/data.pkl`. That member is the marker pickle from `marker-pickle`. Intake expands it to depth 1 at `model.bin!/archive/data.pkl`. Expected check `pickle_dangerous_callable`, severity critical, on that inner member.
