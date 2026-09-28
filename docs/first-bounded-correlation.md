# TraceSOC First Bounded Correlation

## Phase

3D.

## Correlation

`TRC-CORR-001`

PowerShell web-retrieval behavior corroborated by Zeek network telemetry.

## Inputs

- one matched `TRC-DET-001` result;
- the contributing PowerShell `SemanticEvent`;
- one Zeek `SemanticEvent`.

## Required relationship

A correlation is formed only when all of these agree:

1. TRC-DET-001 matched the PowerShell event;
2. both observations identify the same host;
3. PowerShell `local_ip` equals Zeek `src_ip`;
4. an HTTP(S) URI is extracted from the PowerShell script;
5. the URI uses an IP-literal destination;
6. URI destination IP equals Zeek `dst_ip`;
7. URI destination port equals Zeek `dst_port`;
8. Zeek occurs after the PowerShell event;
9. the difference is no greater than 60 seconds.

Time adjacency alone cannot produce this correlation.

## Current DNS limitation

The first correlation deliberately requires an IP-literal URI.

It does not perform DNS inference.

A hostname-based URI is therefore SEARCH_NOT_CLOSED for this correlation
until independent DNS evidence is introduced in later real-data work.

## FINDING-001

The first finding separates:

- observed facts;
- inference;
- confidence and confidence scope;
- alternative explanation;
- falsifier;
- residual risk;
- business impact;
- decision required;
- recommended action;
- response-validation state;
- evidence references;
- detection ID;
- correlation ID;
- correlation-edge ID.

## Claim boundary

FINDING-001 establishes:

> PowerShell web-retrieval behavior is corroborated by independent network
> telemetry to the same destination under the explicit correlation
> constraints.

It does not establish:

- malicious intent;
- malware;
- compromise;
- retrieved-content identity;
- successful payload execution;
- initial access;
- business impact.

## Evidence path

The finding contains raw-evidence references for both contributing events.

Each reference carries:

- event ID;
- source family;
- logical source;
- record index;
- line number;
- byte offset;
- byte length;
- raw SHA-256.

## Synthetic status

FINDING-001 is generated from architecture-validation fixtures.

It must never be represented as a real incident finding.

## Anti-drift

Production detector count remains exactly one.

The next phase is explanation of FINDING-001, not another detector.