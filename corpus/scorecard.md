# Corpus scorecard

Generated 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30).

Clock times in this file are Asia/Calcutta (UTC+5:30).

## Metrics

| Metric | Value |
| --- | --- |
| Detection rate (strict) | 1.000 (8/8) |
| Caught rate (exit non-zero) | 1.000 (8/8) |
| False-positive rate | 0.000 (0/2) |
| Scan time | 112.732 ms |

Strict detection rate is the number of suspicious rows whose exit code is non-zero and whose findings or checks include every expected check id, divided by the number of suspicious rows. A suspicious row that exits non-zero for a different reason is a miss, not a detection. Caught rate is the number of suspicious rows with a non-zero exit code, divided by the number of suspicious rows.

False-positive rate is the number of clean rows that exit 30 or 10, or that have any finding with severity warning or critical, divided by the number of clean rows. Exit 20 with only skipped coverage gaps is not a false positive.

Scan time is the wall time around each scan call, in milliseconds, plus the total.

## Artifacts

| Artifact | Label | Exit | Verdict | Strict | Caught | False positive | Scan time (ms) | Scanned at | Expected check |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| tiny-full-model | clean | 20 | Undetermined rule_insufficient_evidence | no | no | no | 11.768 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | none |
| tiny-lora | clean | 20 | Undetermined rule_insufficient_evidence | no | no | no | 11.644 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | none |
| marker-pickle | suspicious | 30 | Blocked rule_critical | yes | yes | no | 10.877 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | pickle_dangerous_callable |
| disguised-pickle | suspicious | 30 | Blocked rule_critical | yes | yes | no | 10.903 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | intake.format_mismatch;pickle_dangerous_callable |
| trailing-bytes | suspicious | 30 | Blocked rule_critical | yes | yes | no | 10.923 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | safetensors_trailing_bytes |
| spoofed-base | suspicious | 10 | Conditional rule_warnings | yes | yes | no | 11.570 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | provenance_base_claim |
| lookalike-name | suspicious | 10 | Conditional rule_warnings | yes | yes | no | 10.970 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | provenance_typosquat |
| config-mismatch | suspicious | 30 | Blocked rule_critical | yes | yes | no | 11.623 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | provenance_config |
| hash-mismatch | suspicious | 30 | Blocked rule_critical | yes | yes | no | 11.223 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | provenance_hash_match |
| nested-torch-zip | suspicious | 30 | Blocked rule_critical | yes | yes | no | 11.231 | 2026-11-20 13:02:34 +05:30 (Asia/Calcutta, UTC+5:30) | pickle_dangerous_callable |

## Notes

- **tiny-full-model**: Known-good full model. Registered as acme/tiny-base. Static safetensors checks should pass.
- **tiny-lora**: Known-good LoRA. adapter_config claims base acme/tiny-base. Requires --base acme/tiny-base.
- **marker-pickle**: model.pickle opcode stream GLOBALs os.system and stops. Bytes only; not a payload and not unpickled. os is on the static deny list.
- **disguised-pickle**: Same marker pickle bytes as marker-pickle, saved as model.safetensors. Extension disagrees with pickle magic.
- **trailing-bytes**: Clean full model whose model.safetensors has the ASCII bytes HASHVAULT_MARKER appended and nothing else.
- **spoofed-base**: Clean LoRA weights. adapter_config.json claims base_model_name_or_path evil/not-the-base. Spoofed lineage, not a behavioural backdoor.
- **lookalike-name**: Clean full model bytes plus scan.yaml. Claimed repo is acme/tiny-bose, one character off acme/tiny-base. Scan with --repo acme/tiny-bose.
- **config-mismatch**: expected_check is provenance_config. provenance_hash_match is also present; this row is a strict detection only because provenance_config is present. Clean weights. config.json hidden_size is 999; the registry entry for acme/tiny-base says 8.
- **hash-mismatch**: Clean full model plus README.txt containing the word extra, and scan.yaml claiming repo acme/tiny-base. Root hash differs from the registry.
- **nested-torch-zip**: model.bin is a zip containing archive/data.pkl. That member is the marker pickle. Expected at depth 1 as model.bin!/archive/data.pkl.
