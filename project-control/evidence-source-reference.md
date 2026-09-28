# TraceSOC Evidence Source Reference Catalogue

## Purpose

This is the permanent human-readable provenance and citation catalogue for
evidence used by TraceSOC.

The machine-readable acquisition register and acquisition manifests remain the
integrity authorities.

This document exists so that an assessor or project maintainer can determine:

- exactly what was acquired;
- where it came from;
- when it was acquired;
- the role assigned to it;
- the exact local controlled path;
- its SHA-256;
- its byte size;
- licensing or use terms;
- how to cite the source;
- how to locate or retrieve the upstream source;
- whether the artifact is original, publisher-derived, or project-derived;
- known limitations.

Unknown values must remain UNKNOWN.

---

# SRC-001 — Splunk Attack Data PowerShell Operational Evidence

TraceSOC source ID:

TS-DEV-SPLUNK-PS-001

Role:

DEVELOPMENT

Telemetry family:

POWERSHELL

Publisher:

Splunk Inc.

Source title:

Splunk Attack Data T1087.002 AD discovery PowerShell Operational log

Upstream repository:

https://github.com/splunk/attack_data

Pinned repository commit:

be1980668e58497d23ba77ba25769996c4d1efaa

Upstream relative path:

datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell-xml.log

Exact acquisition URL:

https://media.githubusercontent.com/media/splunk/attack_data/be1980668e58497d23ba77ba25769996c4d1efaa/datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell-xml.log

Acquired UTC:

2026-09-14T13:49:09.3155167Z

Original filename:

windows-powershell-xml.log

Controlled local path:

D:\TraceSOC-Evidence\raw\development\splunk-attack-data\T1087.002\AD_discovery\windows-powershell-xml.log

Byte size:

2038252

SHA-256:

ce45d417d0bd66e05939f835935dd24cfe6f55b257d7b2bb968c726ae378c8c3

License / terms:

Apache-2.0

Artifact class:

PUBLISHER-PROVIDED RAW/REPLAY EVENT LOG

Publisher context:

The source is part of Splunk Attack Data, a curated repository of attack data
used for detection development and testing.

TraceSOC rule:

Publisher technique names, folder names, labels, and expected detections are
contextual metadata only. They are not production detector selectors.

Recommended project citation:

Splunk Inc. "attack_data" GitHub repository, commit be1980668e58497d23ba77ba25769996c4d1efaa,
datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell-xml.log,
Apache License 2.0. Accessed through the exact acquisition URL recorded above.

Reproduction direction:

Retrieve the exact upstream file from the pinned commit shown above and verify
its SHA-256 equals:

ce45d417d0bd66e05939f835935dd24cfe6f55b257d7b2bb968c726ae378c8c3

Known limitations:

Curated attack dataset; DEVELOPMENT only; event semantics not yet parsed or independently adjudicated

---

# SRC-002 — IoT-23 Capture-34-1 Publisher Metadata

TraceSOC source ID:

TS-DEV-IOT23-034-META

Role:

DEVELOPMENT

Publisher:

Stratosphere Laboratory / CTU

Exact acquisition URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/README.md

Acquired UTC:

2026-09-14T13:49:09.3155167Z

Controlled local path:

D:\TraceSOC-Evidence\raw\development\iot23\CTU-IoT-Malware-Capture-34-1\README.md

Byte size:

1596

SHA-256:

940e8778cba292b4c9d2f8b7e10d77976c8eccfc8b6b8bfa79faa53230203f7f

Artifact class:

PUBLISHER PROVENANCE METADATA

Use terms recorded at acquisition:

Publisher FAQ states permission is not required with appropriate citation

Recommended dataset citation:

Sebastian Garcia, Agustin Parmisano, and Maria Jose Erquiaga. 2020.
IoT-23: A labeled dataset with malicious and benign IoT network traffic,
Version 1.0.0. Zenodo. DOI: 10.5281/zenodo.4743746.

Official dataset page:

https://www.stratosphereips.org/datasets-iot23

Publisher FAQ / permission guidance:

https://www.stratosphereips.org/datasets-faq

Important limitation:

Individual README contains legacy authorization wording; current publisher FAQ states permission is not required if appropriately cited

---

# SRC-003 — IoT-23 Capture-34-1 Original PCAP

TraceSOC source ID:

TS-DEV-IOT23-034-PCAP

Role:

DEVELOPMENT

Telemetry family:

NETWORK / ORIGINAL PCAP

Publisher:

Stratosphere Laboratory / CTU

Exact acquisition URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.pcap

Acquired UTC:

2026-09-14T13:49:09.3155167Z

Original filename:

2018-12-21-15-50-14-192.168.1.195.pcap

Controlled local path:

D:\TraceSOC-Evidence\raw\development\iot23\CTU-IoT-Malware-Capture-34-1\2018-12-21-15-50-14-192.168.1.195.pcap

Byte size:

126317980

SHA-256:

92ec7e2f6658ee4b007d0b816986c46cc0338bc5e2bec6ceaaca566c695e4699

Artifact class:

ORIGINAL PACKET CAPTURE

Relationship:

This PCAP is the original network evidence for IoT-23 Capture-34-1.

It is the provenance anchor for any TraceSOC-derived network representation
created from this capture.

Recommended citation:

Use the IoT-23 dataset citation recorded under SRC-002 and identify this exact
scenario and filename.

Known limitations:

IoT network context; does not establish Windows endpoint behavior; packet contents not yet analytically inspected

Reproduction direction:

Retrieve the exact PCAP from the recorded acquisition URL and verify SHA-256:

92ec7e2f6658ee4b007d0b816986c46cc0338bc5e2bec6ceaaca566c695e4699

---

# SRC-004 — IoT-23 Capture-34-1 Publisher Zeek conn.log

TraceSOC source ID:

TS-DEV-IOT23-034-ZEEK

Role:

DEVELOPMENT

Telemetry family:

ZEEK

Publisher:

Stratosphere Laboratory / CTU

Exact acquisition URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled

Acquired UTC:

2026-09-14T13:49:09.3155167Z

Original filename:

conn.log.labeled

Controlled local path:

D:\TraceSOC-Evidence\raw\development\iot23\CTU-IoT-Malware-Capture-34-1\bro\conn.log.labeled

Byte size:

2926718

SHA-256:

d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e

Artifact class:

PUBLISHER-DERIVED ZEEK CONNECTION LOG

Derivation relationship:

The publisher states that conn.log.labeled is produced by running Zeek on the
original PCAP.

Original provenance anchor:

TS-DEV-IOT23-034-PCAP

Labels:

The file contains publisher-added labels.

TraceSOC rule:

Publisher labels must remain contextual metadata and must not become hidden
production detector selectors.

Recommended citation:

Use the IoT-23 dataset citation under SRC-002, identify Capture-34-1, and state
that this artifact is the publisher-provided Zeek conn.log derived from the
scenario's original PCAP.

Known limitations:

Derived from publisher PCAP; labels must remain outside detector-facing semantics; Zeek compatibility not yet tested

Reproduction direction:

Retrieve the exact upstream conn.log.labeled and verify SHA-256:

d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e

---

# Current corpus completeness

The current real corpus is NOT complete.

Real telemetry families currently represented:

- POWERSHELL
- ZEEK / NETWORK

Required real telemetry families still missing:

- SYSMON
- WINDOWS_SECURITY

Additional validation still required:

- network benign controls;
- endpoint benign control evidence;
- isolated holdout evidence;
- multiple suspicious scenarios;
- scale evidence after correctness;
- derived duplicate/malformed/timing challenge corpus.

No claim should state that the final TraceSOC evidence corpus is complete until
the coverage matrix shows all mandatory requirements satisfied.

---

# Citation rule for final reporting

Every material report claim derived from external evidence must be traceable to:

TraceSOC source ID
-> acquisition register row
-> exact upstream source
-> local immutable path
-> SHA-256
-> raw locator
-> canonical event
-> analytic result
-> report claim.

The final report must cite the publisher/dataset and preserve the TraceSOC
source ID so an assessor can follow the complete chain.
---

# SRC-005 — Splunk Attack Data Sysmon Evidence

TraceSOC source ID:

TS-DEV-SPLUNK-SYSMON-001

Role:

DEVELOPMENT

Telemetry family:

SYSMON

Publisher:

Splunk Inc.

Upstream repository:

https://github.com/splunk/attack_data

Pinned repository commit:

be1980668e58497d23ba77ba25769996c4d1efaa

Upstream relative path:

datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log

Exact acquisition URL:

https://media.githubusercontent.com/media/splunk/attack_data/be1980668e58497d23ba77ba25769996c4d1efaa/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log

Acquired UTC:

2026-09-14T14:20:41.8097466Z

Original filename:

windows-sysmon.log

Controlled local path:

D:\TraceSOC-Evidence\raw\development\splunk-attack-data\T1562.001\win_app_defender_disabling\windows-sysmon.log

Byte size:

20091826

SHA-256:

8886e363b137555f5a0403783106e656b77e328fab2e503a645015f5e1cc3756

License / terms:

Apache-2.0

Publisher source classification:

XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

Publisher scenario context:

T1562.001 / win_app_defender_disabling

TraceSOC rule:

Scenario and ATT&CK metadata remain contextual metadata only and may not become
hidden production selectors.

Reproduction direction:

Retrieve the exact file from the pinned commit and verify SHA-256:

8886e363b137555f5a0403783106e656b77e328fab2e503a645015f5e1cc3756

---

# SRC-006 — Splunk Attack Data Windows Security Evidence

TraceSOC source ID:

TS-DEV-SPLUNK-SECURITY-001

Role:

DEVELOPMENT

Telemetry family:

WINDOWS_SECURITY

Publisher:

Splunk Inc.

Upstream repository:

https://github.com/splunk/attack_data

Pinned repository commit:

be1980668e58497d23ba77ba25769996c4d1efaa

Upstream relative path:

datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-security.log

Exact acquisition URL:

https://media.githubusercontent.com/media/splunk/attack_data/be1980668e58497d23ba77ba25769996c4d1efaa/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-security.log

Acquired UTC:

2026-09-14T14:20:41.8097466Z

Original filename:

windows-security.log

Controlled local path:

D:\TraceSOC-Evidence\raw\development\splunk-attack-data\T1562.001\win_app_defender_disabling\windows-security.log

Byte size:

8490471

SHA-256:

b55c57fd0256fa73f55116f9ad307de3b7403f1ba7536c10431b56426a09bd89

License / terms:

Apache-2.0

Publisher source classification:

WinEventLog:Security

Publisher scenario context:

T1562.001 / win_app_defender_disabling

TraceSOC rule:

Publisher scenario labels and expected outcomes remain contextual metadata
only.

Reproduction direction:

Retrieve the exact file from the pinned commit and verify SHA-256:

b55c57fd0256fa73f55116f9ad307de3b7403f1ba7536c10431b56426a09bd89

---

# Four-family real telemetry milestone

Real TraceSOC telemetry families now represented:

- POWERSHELL
- ZEEK / NETWORK
- SYSMON
- WINDOWS_SECURITY

The minimum four-family real-telemetry requirement is now satisfied.

The final evidence corpus is still incomplete.

Outstanding work includes:

- benign network controls;
- benign endpoint evidence;
- isolated holdout;
- additional suspicious scenario diversity;
- derived malformed/duplicate/timing challenge cases;
- scale evidence;
- real-format production adapter validation.
---

# SRC-007 — IoT-23 v2 Philips Hue Benign Control

Scenario:

CTU-Honeypot-Capture-4-1

Role:

BENIGN_CONTROL

Publisher:

Stratosphere Laboratory / CTU

Publisher classification:

BENIGN

Device:

Philips Hue

Upstream dataset version:

IoT-23 v2

Publisher caveat:

Version 2 is described as work in progress, so TraceSOC evidence identity is
defined by the exact artifact locators and SHA-256 values below.

## Provenance metadata

TraceSOC source ID:

TS-BEN-IOT23V2-HUE-META

Exact acquisition locator:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-4-1/README.md

Controlled local path:

D:\TraceSOC-Evidence\raw\benign_control\iot23-v2\CTU-Honeypot-Capture-4-1\README.md

Byte size:

2292

SHA-256:

e373dc756f23f78677de625861a1052623238cd32a5fdf61d22f6b1f12da48b4

## Original PCAP

TraceSOC source ID:

TS-BEN-IOT23V2-HUE-PCAP

Exact acquisition locator:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-4-1/pcap/2018-10-25-14-06-32-192.168.1.132.pcap

Controlled local path:

D:\TraceSOC-Evidence\raw\benign_control\iot23-v2\CTU-Honeypot-Capture-4-1\2018-10-25-14-06-32-192.168.1.132.pcap

Byte size:

4594492

SHA-256:

f770897e6cc3fa45857aee25ef7d3ab39dba39127b5bb813e0e0d48d3b905347

## Publisher-labeled Zeek connection log

TraceSOC source ID:

TS-BEN-IOT23V2-HUE-ZEEK

Exact acquisition locator:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132-zeek-conn.log.labeled

Controlled local path:

D:\TraceSOC-Evidence\raw\benign_control\iot23-v2\CTU-Honeypot-Capture-4-1\2018-10-25-14-06-32-192.168.1.132-zeek-conn.log.labeled

Byte size:

61653

SHA-256:

aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e

Citation:

Sebastian Garcia, Agustin Parmisano, and Maria Jose Erquiaga. IoT-23:
A labeled dataset with malicious and benign IoT network traffic.

Usage condition recorded by TraceSOC:

Publisher permits dataset use with appropriate citation.

TraceSOC boundary:

The publisher's BENIGN classification is evaluation/context metadata.
It is not a detector selector.

---

# SRC-008 — IoT-23 v2 Amazon Echo Benign Control

Scenario:

CTU-Honeypot-Capture-5-1

Role:

BENIGN_CONTROL

Publisher:

Stratosphere Laboratory / CTU

Publisher classification:

BENIGN

Device:

Amazon Echo Dot

Upstream dataset version:

IoT-23 v2

Publisher caveat:

Version 2 is described as work in progress, so TraceSOC evidence identity is
defined by the exact artifact locators and SHA-256 values below.

## Provenance metadata

TraceSOC source ID:

TS-BEN-IOT23V2-ECHO-META

Exact acquisition locator:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-5-1/README.md

Controlled local path:

D:\TraceSOC-Evidence\raw\benign_control\iot23-v2\CTU-Honeypot-Capture-5-1\README.md

Byte size:

2298

SHA-256:

8cced12e6754434021da1ec7ff63305605bc6ebca43f6eb1b3ee7414674ad5fb

## Original PCAP

TraceSOC source ID:

TS-BEN-IOT23V2-ECHO-PCAP

Exact acquisition locator:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-5-1/pcap/2018-09-21-11-40-22-192.168.2.3.pcap

Controlled local path:

D:\TraceSOC-Evidence\raw\benign_control\iot23-v2\CTU-Honeypot-Capture-5-1\2018-09-21-11-40-22-192.168.2.3.pcap

Byte size:

381382500

SHA-256:

f7867a836e416d6914aa56ddf6d75abe05453c7aa03851d108678e4c2688cca7

## Publisher-labeled Zeek connection log

TraceSOC source ID:

TS-BEN-IOT23V2-ECHO-ZEEK

Exact acquisition locator:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-5-1/2018-09-21-11-40-22-192.168.2.3-zeek-conn-log.labeled

Controlled local path:

D:\TraceSOC-Evidence\raw\benign_control\iot23-v2\CTU-Honeypot-Capture-5-1\2018-09-21-11-40-22-192.168.2.3-zeek-conn-log.labeled

Byte size:

182147

SHA-256:

f36db06e7d6ba7364e932a5b003f75835e004b320d70019e8a2f0ba8685d9262

Citation:

Sebastian Garcia, Agustin Parmisano, and Maria Jose Erquiaga. IoT-23:
A labeled dataset with malicious and benign IoT network traffic.

Usage condition recorded by TraceSOC:

Publisher permits dataset use with appropriate citation.

TraceSOC boundary:

The publisher's BENIGN classification is evaluation/context metadata.
It is not a detector selector.
---

# SRC-009 — Nextron Systems Windows 10 Goodware Endpoint Baseline

TraceSOC source ID:

TS-BEN-NEXTRON-WIN10-ARCHIVE

Role:

BENIGN_CONTROL

Publisher:

Nextron Systems

Project:

evtx-baseline

Release:

v0.8.4

Original release asset:

win10-client.tgz

Exact acquisition URL:

https://github.com/NextronSystems/evtx-baseline/releases/download/v0.8.4/win10-client.tgz

Acquired UTC:

2026-09-15T07:49:08.6997867Z

Controlled immutable raw path:

D:\TraceSOC-Evidence\raw\benign_control\nextron-evtx-baseline\v0.8.4\win10-client.tgz

Byte size:

70844052

Publisher-provided SHA-256:

d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e

TraceSOC observed SHA-256:

d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e

Publisher hash match:

PASS

License / terms:

Apache-2.0 repository license.

Artifact class:

PUBLISHER RELEASE ARCHIVE / IMMUTABLE RAW EVIDENCE

Publisher context:

The corpus is described as example goodware Windows EVTX generated through
normal software installation and basic user interaction.

TraceSOC boundary:

The goodware/benign classification is contextual evidence and is not a
production detector selector.

## Derived selected EVTX

The source archive remains unchanged.

### Windows Security

Archive member:

Logs_Client/Security.evtx

Derived path:

D:\TraceSOC-Evidence\derived\benign_control\nextron-evtx-baseline\v0.8.4\win10-client\Security.evtx

Derived SHA-256:

543f73f57f0b9a682a3a6e7bdab890e94484c86dc1771e5780e481386a6044fe

### Sysmon Operational

Archive member:

Logs_Client/Microsoft-Windows-Sysmon%4Operational.evtx

Derived path:

D:\TraceSOC-Evidence\derived\benign_control\nextron-evtx-baseline\v0.8.4\win10-client\Microsoft-Windows-Sysmon%4Operational.evtx

Derived SHA-256:

efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb

### PowerShell Operational

Archive member:

Logs_Client/Microsoft-Windows-PowerShell%4Operational.evtx

Derived path:

D:\TraceSOC-Evidence\derived\benign_control\nextron-evtx-baseline\v0.8.4\win10-client\Microsoft-Windows-PowerShell%4Operational.evtx

Derived SHA-256:

fc95504793682c73aece8e89c7d799545a5b607119afe3466c3e879ca8db1464

## Parent lineage

Every selected EVTX retains parent archive SHA-256:

d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e

## Acquisition recovery note

The first Phase 4C.5 attempt stopped before raw storage because the temporary
selected-evtx directory was pre-created by PowerShell while the safe Python
inspector required that output directory not to exist.

The downloaded archive had already passed the publisher SHA-256 check.

TraceSOC verified that:

- the acquisition register remained unchanged;
- existing raw evidence remained 12/12 hash valid;
- the failed extraction directory was empty;
- the previously downloaded archive still matched the publisher SHA-256.

The verified download was reused without redownloading.

No external raw evidence was altered by the failed attempt.

## Attribution

Nextron Systems, evtx-baseline, release v0.8.4, win10-client.tgz.

Repository:

https://github.com/NextronSystems/evtx-baseline

Release:

https://github.com/NextronSystems/evtx-baseline/releases/tag/v0.8.4
---

# SRC-010 — IoT-23 v2 Sealed Network Holdout / Muhstik

Candidate:

CAND-011

Role:

HOLDOUT

Dataset:

IoT-23 v2

Scenario:

CTU-IoT-Malware-Capture-3-1

Publisher:

Stratosphere Laboratory / CTU

Publisher scenario:

Muhstik

Device:

Raspberry Pi

Publisher capture metadata:

- Start: 2018-05-19
- Duration: 36.12 hours
- Host: 192.168.2.5
- Gateway: 192.168.2.1
- Packets: 496,959
- Original capture size: approximately 56 MB

## Provenance metadata artifact

TraceSOC source ID:

TS-HOLD-IOT23V2-003-META

Exact URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/README.md

Sealed path:

D:\TraceSOC-Evidence\holdout\sealed\iot23-v2\CTU-IoT-Malware-Capture-3-1\README.md

Byte size:

2649

SHA-256:

7d82a173d60a19cbf7296cf58bdb828a10c536dced852d77cbde22b771265d37

Access class:

PROVENANCE_METADATA_ACCESS

## Sealed semantic holdout payload

TraceSOC source ID:

TS-HOLD-IOT23V2-003-ZEEK

Artifact:

plain Zeek conn.log

Exact URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/zeek-labeled/conn.log

Sealed path:

D:\TraceSOC-Evidence\holdout\sealed\iot23-v2\CTU-IoT-Malware-Capture-3-1\conn.log

Byte size:

17387889

SHA-256:

1481a5c82b96ce3b902e383b7da7dbebc0466275af6a8bfaf1b453443bd2c7ba

Access class before analytic freeze:

INTEGRITY_ONLY_ACCESS

Semantic payload inspected:

FALSE

Publisher labels accessed:

FALSE

Detector execution:

FALSE

## Deliberately not acquired

Publisher-labeled connection log:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/2018-05-19-20-57-19-192.168.2.5-zeek-conn-log.labeled

labels.config:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/2018-05-19-20-57-19-192.168.2.5-labels.config

PCAP:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/pcap/2018-05-19-20-57-19-192.168.2.5.pcap

## Evidence identity

IoT-23 v2 is described by the publisher as work in progress.

Therefore this TraceSOC copy is identified by:

- exact publisher URL;
- acquisition UTC;
- observed byte size;
- TraceSOC SHA-256;
- post-storage SHA-256 equality;
- sealed local path;
- read-only protection.

## Holdout rationale

TraceSOC network development evidence includes IoT-23 Capture 34-1 / Mirai.

The holdout is Capture 3-1 / Muhstik.

This creates malware-family and traffic-instance diversity.

Known limitation:

Both are from the IoT-23 corpus.

Cross-publisher network holdout diversity is therefore NOT ESTABLISHED.

## Historical holdout selection

CAND-005 / Hajime was initially selected but superseded before semantic use
because its plain connection log was approximately 668 MB.

A partial transport of 47,871,986 bytes occurred in scratch and was safely
aborted and deleted.

It never entered sealed storage or the acquisition register and was never
semantically inspected.

## Citation

Sebastian Garcia, Agustin Parmisano, Maria Jose Erquiaga.
IoT-23: A labeled dataset with malicious and benign IoT network traffic.

Publisher:

Stratosphere Laboratory / CTU.

## Next use

No semantic use of TS-HOLD-IOT23V2-003-ZEEK is permitted until a committed
TraceSOC analytic-freeze proof exists.
---

# Phase 4D.2 Sysmon zero-record adjudication

Artifact:

Microsoft-Windows-Sysmon%4Operational.evtx

SHA-256:

efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb

Byte size:

799084544

Windows offline metadata:

numberOfLogRecords = 0

Current interpretation:

CONFIRMED_ZERO_RECORD_LOG

Integrity/extraction failure:

NOT SUPPORTED BY EVIDENCE

Corruption:

NOT CLAIMED

Populated benign Sysmon events:

NOT ESTABLISHED

Endpoint benign-control status:

REMAINS ACQUIRED through the Nextron source, with populated Security and
PowerShell channels.

The large EVTX byte size must not be interpreted as proof of populated event
records.

The 2026 filesystem creation/access/write timestamps reported for the extracted
file are local storage metadata and are not source telemetry timestamps.

---

# Phase 4D.3X post-hoc labeled holdout acquisition

## Post-hoc publisher-labeled scoring artifact

TraceSOC source ID:

TS-HOLD-IOT23V2-003-ZEEK-LABELED

Artifact:

2018-05-19-20-57-19-192.168.2.5-zeek-conn-log.labeled

Exact publisher URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/2018-05-19-20-57-19-192.168.2.5-zeek-conn-log.labeled

Post-hoc evidence path:

D:\TraceSOC-Evidence\holdout\posthoc\iot23-v2\CTU-IoT-Malware-Capture-3-1\2018-05-19-20-57-19-192.168.2.5-zeek-conn-log.labeled

Byte size:

24383537

Locally captured SHA-256:

9851009bbca03e15089fa1a356dd4b5eee4a98161a51703626058a0b507f50d0

Publisher checksum:

NOT_ESTABLISHED

Access class during acquisition:

INTEGRITY_ONLY_ACCESS

Acquisition completed UTC:

2026-09-16T12:27:15.4876825Z

Label values inspected during acquisition:

FALSE

Rows counted during acquisition:

FALSE

Fields inspected during acquisition:

FALSE

Parser executed during acquisition:

FALSE

Purpose:

Post-hoc publisher scoring evidence for frozen HOLDOUT-EVAL-0001.

Acquisition manifest:

D:\TraceSOC-Evidence\manifests\phase4d3x-posthoc-labeled-connlog-acquisition.json

Acquisition manifest SHA-256:

b80fbfadb1510b3d0ee815f8e8cc02c7122f8ed4b825bc16c915924f84afedb0

Boundary:

This artifact is additional evidence. It does not replace the plain sealed holdout conn.log and may not be used as a detector selector.
