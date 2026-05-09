# netscanner-plugins

All protocol plugins for [netscanner](https://github.com/fuhdan/netscanner).

Plugins are developed and reviewed here. When a plugin is merged, a pipeline
automatically syncs it into the main netscanner repo — so users always get
all plugins when they update netscanner.

---

## Available plugins

| Plugin | Port | Docs |
|--------|------|------|
| `modbus` | 502 | [modbus.md](plugins/modbus.md) |

---

## Contributing a plugin

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

In short: add `plugins/yourprotocol.py`, `plugins/yourprotocol.md`, and
`tests/test_plugin_yourprotocol.py`, then open a PR. CI will validate
everything automatically.
