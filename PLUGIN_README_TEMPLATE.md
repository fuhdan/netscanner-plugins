# netscanner-plugin-yourprotocol

One-line description of what this plugin scans for.

## Protocol

Brief explanation of the protocol — what it is, what devices use it, why scanning it is useful.
2-3 sentences is enough.

## Installation

```bash
# Clone or download this repo, then copy the plugin into your netscanner installation:
cp plugins/yourprotocol.py /path/to/netscanner/plugins/

# Verify it is discovered:
python3 netscanner.py --list-protocols
```

## Usage

```bash
python3 netscanner.py 10.0.0.0/24 --protocol yourprotocol
```

Optional: document any protocol-specific behaviour worth knowing (e.g. which unit IDs or
function codes are tried, how many packets are sent per host).

## Output fields

| Field | Description | Example |
|-------|-------------|---------|
| `field_name` | What it means | `0x0001` |

These fields appear in the terminal output and in the CSV `--output` file.

## Status codes

| Status | Meaning |
|--------|---------|
| `OPEN` | Device responded correctly to the protocol probe |
| `NO_YOURPROTOCOL` | TCP connected but response was not valid protocol data |

List only codes this plugin produces beyond the framework defaults
(`REFUSED`, `TIMEOUT_CONNECT`, `TIMEOUT_RESPONSE`, `ZERO_WINDOW`, `CLOSED_IMMEDIATELY`).

## Example output

```
[10.0.0.1]    OPEN        field_name=0x0001   42ms
[10.0.0.2]    REFUSED                          1ms
[10.0.0.3]    NO_YOURPROTOCOL                  18ms
```

## Requirements

- Python 3.9+
- netscanner (any version — list minimum if known)
- Any other dependencies (ideally: none)

## Known limitations / caveats

Anything a user might hit in the field — devices that behave oddly, edge cases the plugin
does not handle, known false positives or negatives.

## Licence

<!-- e.g. MIT -->
