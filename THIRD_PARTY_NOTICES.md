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
