# netscanner-plugins

All protocol plugins for [netscanner](https://github.com/fuhdan/netscanner).

Plugins are developed and reviewed here. This repository is the single source
of truth for every plugin, bundled and community alike. When a plugin is merged,
a pipeline validates it, opens a pull request on the main netscanner repo and
queues it for auto-merge — so users get all plugins when they update netscanner.

---

## Available plugins

| Plugin | Port | Docs |
|--------|------|------|
| `modbus` | 502 | [modbus.md](plugins/modbus.md) |
| `opcua` | 4840 | [opcua.md](plugins/opcua.md) |

Both are reference implementations of the plugin contract as much as they are
useful scanners. They happen to be industrial protocols because those came
first; nothing in netscanner is specific to OT, and a plugin for any other TCP
protocol is the same three files.

---

## Contributing a plugin

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

In short: add `plugins/yourprotocol.py`, `plugins/yourprotocol.md`, and
`tests/test_plugin_yourprotocol.py`, then open a PR. CI will validate
everything automatically.

---

## Licence

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are
accepted under the same licence, which is what lets a merged plugin ship inside
netscanner's own releases.
