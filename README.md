# Experimental Suricata 8.0 nDPI 5 Plugin

This is an example of what a Rust plugin, wrapping a C library could look like
as a Suricata 8.0.x plugin.

Note that this is an experimental proof of concept. Suricata 9.0 will have
proper supported bindings for such plugins.

## Downloads

A pre-built Linux x86_64 plugin (`ndpi.so`) can be downloaded from the
[releases](https://github.com/jasonish/suricatax80-ndpi5-plugin/releases)
page.

## Building

MSRV: Rust 1.75.0.

This crate depends on the `suricatax80-plugin-utils` crate.

```sh
cargo build --release
```

The plugin shared object is written to:

```text
target/release/libndpi.so
```

Configure Suricata with the resulting plugin path, for example:

```yaml
plugins:
  - /path/to/target/release/libndpi.so
```

## Licensing

The plugin's own handwritten Rust code is licensed under **LGPL-3.0-only**.
See [LGPLv3](LICENSES/LGPL-3.0-only.txt) and the
[GPLv3 text it incorporates](LICENSES/GPL-3.0-only.txt). This grant does not
relicense nDPI, generated bindings, or other third-party code.

The binary plugin statically embeds nDPI 5.0, which is licensed under
**LGPL-3.0-or-later**; see its [COPYING](ndpi-sys/vendor/nDPI/COPYING) file
and source notices. Unlike nDPI 6.0, this version has no commercial-license
requirement for selected dissectors. Bundled third-party components retain
their respective licenses.

The `LGPL-3.0-only` string reported at runtime describes the plugin's license.
It is not a complete third-party license inventory or a claim of license
compatibility.

### Known GPLv2-only compatibility issue

Combining this LGPLv3 plugin with GPL-2.0-only Suricata creates a license
incompatibility absent additional permissions. Consult your legal team before
redistributing the combined work.
