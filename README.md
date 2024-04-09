# Journald plugin for Falco

This plugin lets you match Falco rules against journald messages (effectively, all your system logs).

## Installation

### Prerequisites

1. The Rust toolchain: https://rustup.rs/
2. libsystemd headers, e.g. `sudo apt install libsystemd-dev` for Debian-like systems.

### Building

Run `cargo build --release` in the source directory.

```
git clone https://github.com/gnosek/falco-journald-plugin
cd falco-journald-plugin
cargo build --release
```

### Installation

Copy the compiled file into your Falco plugin directory

```
sudo cp target/release/libfalco_journald_plugin.so /usr/share/falco/plugins
```

## Usage

### Enabling the plugin

First, enable the plugin in your `falco.yaml`, for example:

```yaml
plugins:
  - name: journald
    library_path: libfalco_journald_plugin.so
    init_config:
      filter:
        - _TRANSPORT=kernel
load_plugins:
  - journald
```

Then, configure filtering. In the example above, the plugin will only receive messages from the kernel.
For more information about filtering, please see
the [systemd documentation](https://www.freedesktop.org/software/systemd/man/latest/sd_journal_add_match.html).

**Note**: specifying a filter item as `AND` or `OR` will insert a conjunction/disjunction respectively,
as described in the linked docs. This enables construction of complex filters.

### Writing rules

The plugin returns all events matching the journal filter as JSON objects, but also provides some helpers to extract
individual fields:

| Field                  | Contents                                                     |
|------------------------|--------------------------------------------------------------|
| `journal.message`      | the actual log message                                       |
| `journal.priority`     | message priority, as an integer (0 is emergency, 7 is debug) |
| `journal.priority_str` | message priority as a string                                 |
| `journal.facility`     | syslog facility as an integer                                |
| `journal.facility_str` | syslog facility as a string                                  |
| `journal.transport`    | the transport which received the message                     |
| `journal.field[NAME]`  | the raw `NAME` field from the message as a string            |

For example, to match messages about interfaces entering/leaving promiscuous mode, you could use a rule like:

```yaml
- rule: promiscuous mode changed
  desc: match whenever an interface enters/leaves promiscuous mode
  condition: journal.priority == 6 and journal.transport == "kernel" and journal.message contains "promiscuous"
  output: "%journal.field[_HOSTNAME]: %journal.message"
  priority: INFO
  source: journal
```

**Note**: to dump the whole JSON event (e.g. to inspect additional fields), use `%evt.plugininfo` as an output field