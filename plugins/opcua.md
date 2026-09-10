# OPC-UA Plugin

Scans for OPC-UA servers on port 4840. Common in modern industrial automation,
MES/SCADA integration layers, IIoT gateways, and any vendor equipment that has
moved on from Modbus.

## Protocol

OPC-UA carries its binary protocol over TCP (port 4840) using the OPC UA
Connection Protocol (UACP). Every message begins with an 8-byte header: a
3-byte ASCII message type, a chunk-type byte (`F` for the handshake messages),
and a little-endian `MessageSize` that includes the header itself.

The plugin sends a single `HEL` (Hello) message advertising the endpoint URL
`opc.tcp://<ip>:<port>` along with the client's protocol version and buffer
limits. A server that speaks OPC-UA answers with either `ACK` (Acknowledge),
carrying its own negotiated limits, or `ERR` (Error), carrying a StatusCode
explaining the rejection. Both are positive identifications — nothing but an
OPC-UA server replies to a Hello with a well-formed UACP frame.

Only one Hello is sent per host. Unlike Modbus, OPC-UA offers no second
attempt on the same connection: after a Hello the server expects an
`OpenSecureChannel`, and it closes the connection once it has sent an Error.

## Installation

None. Merged plugins are synced into netscanner, so a current netscanner
checkout already has this plugin. Verify with:

```bash
python3 netscanner.py --list-protocols
```

## Usage

```bash
python3 netscanner.py 10.0.0.0/24 --protocol opcua
python3 netscanner.py 10.0.0.1 --protocol opcua --port 48010
```

## Output fields

On `OPEN`, the five limits the server negotiated in its Acknowledge:

| Field | Description | Example |
|-------|-------------|---------|
| `protocol_version` | UACP protocol version the server speaks | `0` |
| `receive_buffer` | Largest message the server will receive, in bytes | `65536` |
| `send_buffer` | Largest message the server will send, in bytes | `65536` |
| `max_message_size` | Max total message size (`0` = no limit) | `16777216` |
| `max_chunk_count` | Max chunks per message (`0` = no limit) | `5` |

On `UA_ERROR`, the rejection reason:

| Field | Description | Example |
|-------|-------------|---------|
| `status_code` | 32-bit OPC-UA StatusCode from the Error message | `0x80830000` |
| `status_name` | Symbolic name, or the raw hex if unrecognised | `Bad_TcpEndpointUrlInvalid` |

The human-readable reason string, when the server supplies one, lands in the
`detail` column of the CSV.

## Status codes

| Status | Meaning |
|--------|---------|
| `OPEN` | Server answered the Hello with a valid Acknowledge |
| `UA_ERROR` | Server answered with a valid OPC-UA Error — still an OPC-UA server |
| `NO_OPCUA` | TCP connected but the reply was not valid UACP |

`UA_ERROR` most often means the server is healthy but rejected our endpoint
URL, since the plugin cannot know the vendor-specific path a given server
expects. Treat it as a confirmed find.

## Example output

```
[10.0.0.1]    OPEN       protocol_version=0  receive_buffer=65536  send_buffer=65536  max_message_size=16777216  max_chunk_count=5   14ms
[10.0.0.2]    UA_ERROR   status_code=0x80830000  status_name=Bad_TcpEndpointUrlInvalid    9ms
[10.0.0.3]    NO_OPCUA   not a valid OPC-UA Acknowledge or Error   11ms
[10.0.0.4]    REFUSED    connection refused    1ms
```

## Requirements

- Python 3.9+
- netscanner (any version)
- No other dependencies — standard library only

## Known limitations

- Stops at the Hello/Acknowledge handshake. It does not open a SecureChannel,
  so it cannot report endpoint security policies, accepted user-token types,
  the server's application name, or its certificate. Reaching those requires
  an `OpenSecureChannel` with SecurityPolicy `None` followed by `GetEndpoints`.
- Advertises the endpoint URL `opc.tcp://<ip>:<port>` with no path. Servers
  that strictly validate the endpoint URL answer `ERR` with
  `Bad_TcpEndpointUrlInvalid` rather than `ACK`. This still identifies the
  server, but the negotiated buffer limits are not reported in that case.
- Reads the reply with a single `recv()`. An Acknowledge is a fixed 28 bytes
  and arrives whole in practice; a server that fragments it across TCP
  segments would be reported as `NO_OPCUA`.
- Buffer sizes are a weak vendor fingerprint at best. They differ between SDKs
  but are operator-configurable and are clamped by what the client offered.
- Does not scan OPC-UA over HTTPS or WebSockets, only the binary TCP mapping.

## Licence

Apache-2.0, as part of netscanner-plugins.
