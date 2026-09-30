# Experimental Suricata 8.0 nDPI 6 Plugin

This is an example of what a Rust plugin, wrapping a C library could look like
as a Suricata 8.0.x plugin.

Note that this is an experimental proof of concept. Suricata 9.0 will have
proper supported bindings for such plugins.

## Downloads

A pre-built Linux x86_64 plugin (`ndpi.so`) can be downloaded from the
[releases](https://github.com/jasonish/suricatax-ndpi-plugin/releases)
page.

## Building

MSRV: Rust 1.75.0.

This crate depends on the `suricatax80-plugin-utils` crate.

```sh
cargo build --release --locked
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

## nDPI License Type

Starting with nDPI 6.0, some nDPI dissectors (such as TLS, QUIC, DNS and DHCP)
are dual-licensed by ntop. Which dissectors are loaded depends on the license
type nDPI is initialized with. See the nDPI
[licensing terms](ndpi-sys/vendor/nDPI/README.license.md) for details.

The license type is selected with the `ndpi.license` option in
`suricata.yaml`:

```yaml
ndpi:
  license: not-for-profit
```

Valid values are:

- `not-for-profit` (default): all dissectors, including the dual-licensed
  ones, are enabled. For projects where nDPI does not generate direct or
  indirect revenue.
- `for-profit-lgpl`: only the LGPL dissectors are enabled.
- `for-profit-dual-license`: all dissectors are enabled. Requires a commercial
  license agreement with ntop.
