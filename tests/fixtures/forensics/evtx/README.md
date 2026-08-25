# EVTX Process Start Fixtures

These small binary fixtures are pinned copies from
[`sbousseaden/EVTX-ATTACK-SAMPLES`](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES),
which is distributed under GPL-3.0. They are test evidence only and are not
included in the HostHunter module package.

| Local file | Upstream path | SHA-256 | Expected target records |
| --- | --- | --- | --- |
| `security-4688.evtx` | `Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx` | `3ff3fcdb55c08ec0eaa39b25c1e02a205314f367bcedc662586bd063185ca41d` | two Security 4688 records |
| `sysmon-1.evtx` | `Execution/exec_msxsl_xsl_sysmon_1_7.evtx` | `ddaec1c8c49cb3706e9daf184bbcb4c332ae4b148924908ef65acb621ca8e84a` | two Sysmon 1 records and one unrelated record |

The fixture hashes, parser asset digest, parser version, record counts, and
expected normalized ECS output are verified in the package integration lane.
