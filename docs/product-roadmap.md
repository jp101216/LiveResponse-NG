# Core product priorities

The immediate target is a faster, more trustworthy investigation workflow.
Healthcare-specific development is deferred. Features alone do not establish
that LRNG outperforms another product; comparisons need reproducible evidence.

| Priority | Deliverable | Evidence needed to assess it |
| --- | --- | --- |
| 1. Investigation workflow | Offline multi-report cases, source-qualified pivots and conservative before/after persistence comparison | Case/record attribution tests, incomplete-collection fixtures, hostile-input browser checks and analyst task trials |
| 2. Detection validation | Versioned benign/malicious scenario corpus with labeled expected observations and findings | Precision/recall by scenario, false positives on representative clean hosts, documented blind spots and identical-input comparisons |
| 3. Collection reliability | Explicit artifact coverage and performance budgets across Windows/Linux builds and privilege levels | Missed/unreadable artifact counts, runtime, peak memory, bytes read/written, interrupted-run recovery and repeatable OS-matrix results |
| 4. Fleet operations | Authenticated case/job service with SSO, scoped roles, signed/expiring jobs, resumable transfer and action audit | Authorization/tenant-boundary tests, job replay prevention, transport failure tests and an independently reviewed threat model |
| 5. Evidence handling and integrations | Signed manifests, encryption with managed keys, documented retention, stable SIEM/SOAR adapters and support policy | Tamper/decryption tests, key lifecycle checks, schema compatibility, integration fixtures and operational recovery exercises |

The case workspace is the first implemented slice. Its scale benchmark is a
local regression fixture. It does not establish comparative detection quality,
coverage or analyst time savings. Keep measured results, test environments and
limitations with future benchmark reports. Compare relevant workflows with
identical inputs and state clearly which products, versions and configurations
were actually tested.
