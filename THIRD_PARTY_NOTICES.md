# Third-party notices

lrng is MIT licensed (see `LICENSE`). Its binaries also carry the following
third-party data.

## LOLDrivers

The known vulnerable and malicious driver dataset that the `drivers` collector
and the event-log collector's Sysmon driver-load check use
(`internal/vulndrivers/data/loldrivers.tsv`, embedded in the agent) is derived
from [LOLDrivers](https://www.loldrivers.io)
([magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers)),
copyright the LOLDrivers contributors, licensed under the Apache License,
Version 2.0. The full license text is in `LICENSE.loldrivers` (in every
release archive, and at `internal/vulndrivers/data/LICENSE.loldrivers` in the
source tree).

Changes made: `cmd/drivergen` keeps, from LOLDrivers' `drivers.json`, each
driver's identifier, category, verification state, ATT&CK technique, CVEs and
file names, and each sample's file and Authenticode SHA-256 and SHA-1 and
whether it loads with HVCI on, and writes them as sorted, tab-separated text.
The source revision and generation date are recorded at the top of the file
and in every report's `drivers` result (`meta.dataset`).

## MITRE ATT&CK

The ATT&CK technique table that the Navigator export maps findings with
(`internal/attack/data/enterprise.tsv`, embedded in the agent), and the
tactic and technique names in the report viewer's tactic strip
(`viewer/lrng-viewer.html`), are derived from
[MITRE ATT&CK®](https://attack.mitre.org)
([mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)).

© 2026 The MITRE Corporation. This work is reproduced and distributed with
the permission of The MITRE Corporation.

MITRE's license and disclaimers are in `LICENSE.attack` (in every release
archive, and at `internal/attack/data/LICENSE.attack` in the source tree).

Changes made: `cmd/attackgen` keeps, from the Enterprise ATT&CK STIX bundle,
the matrix's tactics in order, and each technique and sub-technique's ID,
name, tactics, and whether it is active, revoked (with the technique that
replaced it) or deprecated, and writes them as sorted, tab-separated text. It
also writes the viewer's tactic and parent-technique table from the same data.
The ATT&CK version, source and generation date are recorded at the top of the
table, and every layer the export writes names the ATT&CK version it was
mapped with (`versions.attack`, and `attack_mapping` in its metadata).
