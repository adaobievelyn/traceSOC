# TraceSOC Phase 4D.3B — Real-Format Raw Readers

## Objective

Implement the first additive real-format ingestion boundary without changing
the established CanonicalEvent model, existing JSONL adapters, detector logic,
correlation logic, or sealed holdout state.

## Implemented

### Windows Event XML stream raw reader

Implemented an exact-byte reader for concatenated Windows Event XML records.

The reader preserves:

- logical source;
- record index;
- first source line;
- exact byte offset;
- exact byte length;
- exact raw-record SHA-256;
- adapter identity;
- input schema version.

Unexpected non-whitespace interstitial bytes and unterminated Event records are
retained as quarantine rather than silently discarded.

No EventID or behavioral semantics are interpreted at this layer.

### Zeek ASCII / TSV raw reader

Implemented a header-aware Zeek ASCII reader.

The reader observes source-declared:

- #separator;
- #fields.

Data rows preserve exact source bytes and exact RawLocator identity.

Publisher label fields are retained only as raw schema values at this layer.

They are not detection selectors.

## Real development evidence validation

PowerShell source:

TS-DEV-SPLUNK-PS-001

Independent records:

126

Reader accepted:

126

Reader quarantined:

0

Locator integrity failures:

0

Sysmon source:

TS-DEV-SPLUNK-SYSMON-001

Independent records:

11618

Reader accepted:

11618

Reader quarantined:

0

Locator integrity failures:

0

Zeek source:

TS-DEV-IOT23-034-ZEEK

Independent records:

23145

Reader accepted:

23145

Reader quarantined:

0

Locator integrity failures:

0

Publisher label columns observed:

True

## Regression

Pre-change suite:

48 / 48 PASS

Focused real-format raw-reader suite:

5 / 5 PASS

Full post-change suite:

53 / 53 PASS

## Harness diagnostic history

Three earlier execution stops were test-harness configuration problems, not
TraceSOC product-test failures:

1. pytest was requested but was not installed;
2. unittest discovery started above the non-package unit-test directory and
   executed zero tests;
3. tests/unit discovery found the modules but repository src was not on
   PYTHONPATH, so test modules could not import TraceSOC.

The valid pre-change baseline was obtained after the src-layout import path was
set explicitly:

48 / 48 PASS.

## Hardcoding control

Production case-specific selector hits:

0

No detector uses:

- candidate IDs;
- fixture IDs;
- expected answers;
- selected evidence hashes;
- malware-family names;
- known attack IP addresses.

## Holdout

Semantic holdout access:

FALSE

Holdout label access:

FALSE

## Explicitly not completed in this phase

- Windows Security multiline text-event reader;
- XML family semantic mapping to CanonicalEvent;
- Zeek connection semantic mapping to CanonicalEvent;
- EVTX extraction boundary.

## Next

Phase 4D.3C — Windows Security Text Reader