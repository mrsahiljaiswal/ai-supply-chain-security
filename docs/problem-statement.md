# ai-supply-chain-security problem statement

ai-supply-chain-security is the name this project uses for an AI supply-chain check that sits between obtaining an external model and integrating it. The brief asks for three inspections — where the artifact came from, whether the files are safe to look at, and whether its behaviour matches the claimed base — and then one evidence-backed decision. This page states the problem, the scope, the deliverables, and the choices the brief leaves open. The longer breakdown is [problem-statement-analysis.md](problem-statement-analysis.md). The chosen shape is in [architecture.md](architecture.md). What is built is in [implementation-solution.md](implementation-solution.md).

## What the project is

The brief titles the work **Project 8 — Adversarial Emulation for the AI Supply Chain**, and describes an AI supply-chain security verification platform. It is a checkpoint: a developer, or a CI job acting for that developer, submits an artifact and receives a trust decision before production use. The decision is one of four verdicts.

| Verdict | Meaning in the brief |
| --- | --- |
| Trusted | Required checks passed with sufficient evidence |
| Conditional | No blocking finding; warnings or incomplete assurances remain |
| Undetermined | Insufficient evidence for a reliable conclusion |
| Blocked | A critical security finding was identified |

The brief does not claim that a passing result is mathematical proof of safety. A scan that finds nothing is not a statement that nothing is there.

**ai-supply-chain-security** is the name this project uses. The brief does not choose that name, and it does not define how ai-supply-chain-security relates to the PDF title. Using ai-supply-chain-security is a naming choice, not a requirement from the brief.

## The core problem

Ordinary software supply chains already have widespread checks for where a package came from and whether its bytes match a published digest. AI applications now pull in a different kind of component: model weights, fine-tuned adapters, datasets, and third-party tool servers. Those components can reach sensitive data and credentials. The brief’s point is that AI supply chains do not yet have the same integrated checks for authenticity, integrity, and security. An attacker can publish a component that looks legitimate and still carries a malicious file or a hidden behaviour.

The check the brief asks for is therefore broader than “does this hash match.” It has to ask where the component came from, what the files contain, how the model behaves against its claimed base, and whether the evidence is enough to trust it.

## The three jobs

The brief’s four objectives collapse, for the build, into three inspections plus one decision.

| Job | What the brief asks it to establish |
| --- | --- |
| Provenance | Publisher, repository, integrity, version or metadata, and claimed lineage |
| Static file safety | Hidden executable code or suspicious structure, without blindly executing the file |
| Behavioural backdoor detection | Difference between the candidate and the claimed base, including trigger-conditioned behaviour |

The fourth objective, trust assessment, is not a fourth inspector. It combines the three reports into one go or no-go, with the evidence attached.

The brief’s design principles for that decision are: one critical finding blocks; a failed or skipped check is never treated as a pass; every verdict carries evidence and artifact hashes; and “no threats found” is not “no threats exist.”

Threats named by the brief and carried into the design are a malicious pickle or other executable payload, a typosquat or fake repository, a backdoored model that looks normal until a trigger, and a spoofed lineage claim.

## What is in scope

The initial implementation in the brief is narrow.

| In scope | Out of scope for the initial implementation |
| --- | --- |
| Self-hosted model weights | Dataset security checks |
| LoRA adapters, plus claimed base-model information | MCP server security checks |
| Repository and publisher metadata supplied with the artifact | |
| CPU-only execution | |
| Small models, about 0.1 billion to 0.5 billion parameters | |
| Static inspection, provenance checks, behavioural comparison, and an evidence-backed verdict | |

Datasets and MCP servers appear in the broader problem. The brief defers both. A design that cannot add them later would fight the brief; building them now is outside the initial scope.

Untrusted files must not be blindly loaded. Docker isolation for controlled analysis is proposed in the brief, not specified as a container contract. CI integration is by process exit codes. GitHub Actions is a proposed consumer of those codes, not a required product.

## Deliverables the brief asks for

The brief’s initial understanding lists six deliverables. Numeric targets for the rates and for scan time are not in the brief.

| # | Deliverable | What “done” means in the brief |
| --- | --- | --- |
| 1 | A command-line tool | Accept an AI artifact and return a verdict |
| 2 | Three independent inspectors | Static scanner, provenance inspector, behavioural inspector |
| 3 | A verdict | One of Trusted, Conditional, Undetermined, Blocked, from hard rules rather than an average score |
| 4 | An evidence bundle | Findings, hashes, and a coverage statement |
| 5 | A CI gate | Exit codes a pipeline can use to allow or hold |
| 6 | A labelled corpus | Clean and deliberately suspicious artifacts, with detection rate, false-positive rate, and scan time |

A limitations document (what the tool can and cannot claim) is the remaining item in that list of six. The validation bar is to measure the corpus, and to demonstrate a backdoored model that looks normal on ordinary inputs and fails a controlled trigger probe.

The brief says functional requirements, module specs, implementation architecture, and the task breakdown are still to be finalised. This page treats the PDF as the initial brief, not a frozen specification.

## Gaps the brief does not decide

Two gaps matter immediately, because the rest of the project documents take a position on them.

* **Product name.** The brief does not name the product ai-supply-chain-security. ai-supply-chain-security is the name this project is using.
* **Exit-code numbers.** The brief requires CI exit codes and does not map them. The mapping 0 Trusted, 10 Conditional, 20 Undetermined, 30 Blocked, and 2 for a usage error before a scan, is a proposal. [architecture.md](architecture.md) records it, and the code uses it.

Other decisions the brief leaves open, all already marked in the analysis:

| Open point | What the brief gives us |
| --- | --- |
| What “sufficient evidence” means for Trusted versus Conditional | The verdict names, and the fail-closed principle. No threshold |
| Detection-rate, false-positive-rate, and scan-time targets | The three metric names. No numbers and no time limit |
| Where known-good hashes and trusted publishers live, and who maintains them | The need for a comparison. No store |
| Whether every scan must have the claimed base model on disk | The behavioural comparison. No offline rule |
| Local CLI only, or also a service | A CLI and a CI gate. Hosting, tenancy, and retention are unspecified |
| GPU or larger models | CPU, and about 0.1B–0.5B parameters, for the initial implementation |

## Where to read next

* [problem-statement-analysis.md](problem-statement-analysis.md) — the longer breakdown, with the brief’s wording, the glossary, and the open questions in full.
* [architecture.md](architecture.md) — one artifact, three inspectors, one verdict, and the rule order the code actually uses.
* [implementation-solution.md](implementation-solution.md) — what is on `main` in the ai-supply-chain-security tree, and what is not built yet.
