# Compliance & Audit Guide

This guide is for **operators** running a Myrmex Hive Gateway and for **auditors**
who need to independently verify what happened on the fleet. It explains what the
Gateway's audit log guarantees, how to verify and export it, how to distribute the
key needed for independent verification, and how these capabilities map onto common
regulatory and framework controls.

> **Framing note.** Myrmex is infrastructure that *supports* and *helps you evidence*
> the controls below. It does not, by itself, certify compliance with any standard.
> Compliance is a property of your whole program (policies, people, and process), of
> which these technical controls are one input.

---

## 1. What the audit log guarantees

When `audit_log_path` is configured, the Gateway records every privileged action to
an append-only, newline-delimited JSON log. Each entry captures who did what, to
which agent, and with what result:

| Field       | Meaning                                                        |
| ----------- | ------------------------------------------------------------- |
| `timestamp` | When the action occurred (RFC 3339).                          |
| `token_id`  | Identifier of the bearer token / principal that acted.        |
| `role`      | RBAC role in effect (`admin` / `operator` / `read-only`).     |
| `action`    | The operation performed (e.g. tool call, config change).      |
| `agent_id`  | Target edge agent, when applicable.                           |
| `command`   | The concrete command executed, when applicable.               |
| `status`    | Outcome (success / failure / denied).                         |
| `details`   | Human-readable context.                                       |
| `prev_sig`  | Signature of the **previous** entry (the hash-chain link).    |
| `signature` | Ed25519 signature over this entry's fields.                   |

Two cryptographic properties make the log trustworthy:

- **Integrity & non-repudiation.** Every entry is signed with the Gateway's
  **Ed25519 SSH host key**. The private key never leaves the Gateway, so a valid
  signature is proof the Gateway — and only the Gateway — produced that entry.
  Any modification to a recorded field invalidates its signature.

- **Tamper-evident chaining.** Each entry embeds `prev_sig`, the signature of the
  entry immediately before it. This links the records into a hash chain: removing,
  reordering, or inserting an entry breaks the chain and is detected on
  verification. You cannot quietly delete a single line without leaving evidence.

Together these mean an auditor can detect **any** alteration, deletion, or forgery
after the fact, using only the log file and the Gateway's *public* key.

---

## 2. How to verify the audit log

Verification is a **local, read-only** operation. It needs only the log file and the
Gateway's host **public** key — no Gateway connection and no auth token:

```bash
myrmex audit verify --log audit.log --host-key host_key.pub
```

`myrmex audit verify` checks, for every entry:

1. **Signature validity** — the Ed25519 signature verifies against the public key.
2. **Chain validity** — each entry's `prev_sig` matches the previous entry's
   `signature`.

It prints a per-line PASS/FAIL table and a summary, and exits non-zero if **any**
signature or chain check fails — making it suitable for CI or a scheduled integrity
check. Add `--output json` for machine-readable results:

```bash
myrmex audit verify --log audit.log --host-key host_key.pub --output json
```

---

## 3. How to export the audit log

To hand the record to a reviewer, archive it, or load it into a SIEM/spreadsheet,
export it. This is also a **local, read-only** operation (no token required):

```bash
# JSON array (default) to stdout
myrmex audit export --log audit.log

# CSV to a file for a compliance reviewer or spreadsheet
myrmex audit export --log audit.log --format csv --out audit.csv
```

- `--format json` (default) emits a single JSON array of all entries.
- `--format csv` emits a header row followed by one row per entry:
  `timestamp,token_id,role,action,agent_id,command,status,details,signature`.
- `--out <file>` writes to a file; otherwise output goes to stdout.

> **Best practice.** Export preserves the raw records but the *authoritative* proof
> of integrity is the signed log. Keep the original signed `audit.log` (and verify
> it) as your source of truth; treat exports as convenience copies for review.

---

## 4. How to distribute the host public key

Independent verification only works if the auditor has the **exact** public key that
corresponds to the Gateway's signing key. Extract it in OpenSSH authorized-key
format straight from the Gateway host:

```bash
myrmex audit pubkey --host-key host_key.pub
```

This validates the file is a well-formed OpenSSH public key and prints it to stdout
(with a one-line explanation on stderr), so you can safely pipe or copy it:

```bash
myrmex audit pubkey --host-key host_key.pub > gateway_audit.pub 2>/dev/null
```

Give `gateway_audit.pub` to the auditor. They run `myrmex audit verify` with it
against the log you exported — verifying integrity **without ever touching the
Gateway or holding any credential**. Only the *public* key is ever distributed; the
private signing key stays on the Gateway.

---

## 5. Control mapping

The table maps Myrmex capabilities to common controls. Claims are framed as
"supports / helps evidence" — Myrmex provides the technical mechanism; you provide
the surrounding policy and process.

| Framework / Regulation | Relevant control area | How Myrmex helps |
| ---------------------- | --------------------- | ---------------- |
| **HIPAA Security Rule** — §164.312(b) Audit controls; §164.312(c) Integrity | Record and examine activity in systems handling ePHI; protect data from improper alteration | Signed, hash-chained audit log records every privileged action and makes tampering detectable; `audit verify` evidences integrity reviews. |
| **SOX** (§404) / **FFIEC** IT Handbook | Logging & monitoring of changes to financial-relevant systems; segregation of duties | Per-token, per-role audit trail attributes each action to a principal; RBAC roles (`admin`/`operator`/`read-only`) support segregation of duties. |
| **CMMC 2.0 / NIST SP 800-171** — AU family (3.3.x) | Create, protect, and retain audit records; ensure actions are traceable to individuals (AU accountability) | Cryptographically signed logs (AU-9 protection of audit info); `token_id` + `role` per entry (traceability); exportable for retention/review. |
| **NIST SP 800-171** — AC (3.1.x) & CM families | Least privilege; limit and control command execution | Command **allowlist** with per-command argument regexes; commands run via `os/exec` (never a shell), removing the shell-injection surface. |
| **CIRCIA** / breach-notification regimes | Reliable incident evidence for reporting timelines | Tamper-evident, timestamped record of fleet actions provides defensible forensic evidence of what occurred and when. |
| **CIS Controls v8** — Control 8 (Audit Log Management), Control 4 (Secure Config) | Collect, protect, and review logs; minimize attack surface | Signed centralized audit log; **zero inbound ports** on targets (agents dial out only) drastically reduces the attack surface subject to review. |

### Supporting architectural controls

Beyond the audit log itself, several Myrmex design choices are directly relevant to
the controls above and worth citing in an assessment:

- **Zero inbound ports on targets.** Agents dial *out* to the Gateway over SSH and
  reject all inbound channels; edge hosts never listen for management traffic. This
  minimizes the externally reachable attack surface (supports CIS Control 4 /
  NIST 800-171 SC & AC families).
- **Command allowlist, no shell.** Only explicitly allowlisted commands run, and
  only when their arguments match a per-command regex; execution is via `os/exec`
  directly, so there is no shell-expansion or injection surface (supports least
  privilege / secure configuration controls).
- **RBAC with signed enforcement.** Bearer tokens map to roles, and role-gated
  actions are recorded in the signed audit log — tying authorization decisions to a
  tamper-evident record (supports access-control and accountability controls).
- **Local LLM orchestration.** The default orchestration path uses a local
  Ollama/Gemma model, so natural-language operator prompts and fleet data need not
  leave the environment — relevant to data-residency and confidentiality
  requirements.

---

*This document describes technical capabilities and does not constitute legal,
regulatory, or certification advice. Consult your compliance function to map these
controls to your specific obligations.*
