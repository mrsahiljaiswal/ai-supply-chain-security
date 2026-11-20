# HashVault (intake stage)

HashVault scans model artifacts (full weights or LoRA adapters plus a claimed base model) and will
issue a Trusted / Conditional / Undetermined / Blocked verdict. This package currently implements the
first two components from `docs/input-components-plan.md`:

1. **Model Artifact / `ScanRequest`** – validated request contract (`hashvault/contracts/request.py`).
2. **Artifact Intake & Manifest** – stage, inventory, expand, detect, hash, classify and extract
   claims without loading any model (`hashvault/intake/`). Output: `ArtifactManifest` plus a list of
   intake `CheckResult`s.

The static, provenance and behavioural inspectors and the verdict engine are not implemented yet.

## Install

```bash
pip install -e '.[dev]'        # add [hub] for Hugging Face hub sources
```

## Usage

```bash
hashvault intake ./models/support-bot-lora \
  --base Qwen/Qwen2.5-0.5B --base-revision <commit> \
  --publisher acme-ml --type lora_adapter --policy strict --out ./reports/

hashvault intake --request scan.yaml        # same fields as ScanRequest; CLI flags override
hashvault intake org/name@<rev> --allow-network --base ...   # needs huggingface_hub
hashvault scan ...                          # stub: runs intake, exits 20 (Undetermined)
```

`intake` prints `{request, manifest, checks}` as JSON (and writes `<scan-id>.intake.json` to `--out`).
Staged files live in `--work-dir` (default `./work`, or `$HASHVAULT_WORK_DIR`) under
`<scan-id>/artifact/` (copied input) and `<scan-id>/expanded/` (archive members, stored as numbered
blobs and never by member name). Both are made read-only after intake.

Exit codes: `2` usage error (bad field, missing path, unknown policy, LoRA without `--base`, hub id
without `--allow-network`); `intake` otherwise exits `0`; the `scan` stub exits `20`.

Example `scan.yaml`:

```yaml
artifact: ./models/support-bot-lora
artifact_type: lora_adapter
claimed_base_model: Qwen/Qwen2.5-0.5B
claimed_publisher: acme-ml
policy_profile: strict
```

## What intake does

| Step | Behaviour |
|------|-----------|
| Stage | Local dir/file/archive copied into quarantine; hub repos resolved to a commit and downloaded (size checked first) |
| Walk | No symlink following; symlinks, hardlinks, devices, fifos recorded in `intake.special_files` |
| Expand | zip (incl. PyTorch zip), tar, tar.gz/bz2/xz, single gzip/bz2/xz streams; recursive, streamed |
| Detect | Magic bytes (safetensors, pickle protocols 0–5, torch zip, npy, joblib, archives, GGUF/HDF5/TFLite/ONNX as `unsupported`, JSON/YAML/Python/text, `unknown`) |
| Hash | Streaming SHA-256 (1 MiB chunks) per file and per member; root hash over sorted `path:sha256` lines |
| Classify | `lora_adapter` / `full_model` (with `config_missing`) / `unknown`; per-file roles |
| Claims | `config.json` / `adapter_config.json` read as JSON text; parameter count from safetensors headers |

Limits and severities come from `policies/strict.yaml` (defaults in `hashvault/policy.py`):
4 GiB total, 10,000 files, nesting depth 5, compression ratio 100:1 (enforced above 1 MiB of output),
4096-byte member paths. A limit breach is an `intake.limits` **error**, the staged files are discarded
and the manifest is returned with `complete: false` and no entries – never a partial inventory.

| Check id | Non-passing outcome |
|----------|---------------------|
| `intake.stage` | `error` (unreadable source, hub failure) |
| `intake.limits` | `error` (limit breached) |
| `intake.inventory` | `error` (unreadable file) |
| `intake.archive_expansion` | `error` (corrupt / encrypted archive) |
| `intake.archive_member_rejected` | `failed`, critical (`..`, absolute path, links, devices, long names) |
| `intake.special_files` | `failed`, warning (symlink/hardlink/device in the source tree) |
| `intake.format_mismatch` | `failed`, warning (extension vs magic bytes) |
| `intake.unsupported_format` | `skipped`, reason `unsupported_format` |
| `intake.unknown_format` | `failed`, warning |
| `intake.type_mismatch` | `failed`, warning (`--type` vs detected) |
| `intake.claims` | `error` (config not valid JSON) |

Intake never unpickles, imports or loads artifact content; it only reads bytes (pickle detection uses
`pickletools.genops`, which disassembles without executing).

## Tests

```bash
python tests/fixtures/generate.py /tmp/fixtures   # optional: inspect fixtures by hand
pytest -q                                          # HASHVAULT_SLOW=1 adds the 2 GiB hashing test
```

Fixtures are generated at test time; "malicious" samples contain only inert marker data.
