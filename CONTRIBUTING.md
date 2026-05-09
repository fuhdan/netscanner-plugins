# Contributing a Plugin

## What belongs here

All protocol plugins — both bundled (modbus) and community contributions.
Each plugin consists of three files:

```
plugins/yourprotocol.py     ← ProtocolPlugin subclass
plugins/yourprotocol.md     ← documentation (required)
tests/test_plugin_yourprotocol.py
```

When your PR is merged here, a pipeline automatically syncs the plugin into
[netscanner](https://github.com/fuhdan/netscanner). Users get it on the next
`git pull` — no separate installation step.

---

## 1. Write the plugin

Your plugin must subclass `ProtocolPlugin`:

```python
from netscanner import ProtocolPlugin, ScanResult, STATUS_OPEN

class YourPlugin(ProtocolPlugin):
    name = "yourprotocol"
    default_port = 1234

    def probe(self, sock, ip, cfg, pcap_writers):
        ...
```

See the [plugin authoring guide](https://github.com/fuhdan/netscanner/blob/main/docs/plugins.md)
for the full interface, pcap tracking pattern, and `plugins/modbus.py` as a real-world example.

## 2. Write the documentation

Copy [PLUGIN_README_TEMPLATE.md](PLUGIN_README_TEMPLATE.md) to
`plugins/yourprotocol.md` and fill in every section. A PR will not be merged
if the documentation is missing or left as placeholders.

Required sections:
- Protocol description
- Usage (exact command)
- Output fields (table)
- Status codes produced by this plugin
- Example output
- Known limitations

## 3. Write the tests

Tests must pass on Python 3.9, 3.11, and 3.12. Use `tests/test_plugin_modbus.py`
as a reference for structure and mock patterns.

CI runs your tests against the latest netscanner by cloning it and copying
your plugin in. If netscanner changes break your plugin, CI will catch it.

## 4. Open a PR

CI will automatically:
- Run `bandit` security scan on `plugins/`
- Clone netscanner and install your plugin
- Verify the plugin is discovered by `--list-protocols`
- Run the full test suite on Python 3.9, 3.11, and 3.12

A maintainer will review code and documentation once CI is green.

### Known bandit false positives

If your plugin uses pcap writers, you will need this line to construct packet headers:

```python
local_ip = "0.0.0.0"  # nosec B104 — pcap source IP, not a socket bind
```

Bandit flags `"0.0.0.0"` as a potential server bind to all interfaces (B104).
It is not — it is a source address used only for synthesizing pcap headers.
The `# nosec B104` annotation suppresses this specific false positive.
Use the exact comment shown so the intent is clear to reviewers.

---

## After merge

A pipeline opens a PR on netscanner with your plugin files. It auto-merges
once netscanner's CI passes. No action needed from you.
