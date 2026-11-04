# GTKGuard

A small, native GTK4 + libadwaita app for bringing [WireGuard](https://www.wireguard.com/) tunnels up and down.
No daemon, no NetworkManager, no tray. One window, one switch per tunnel.

- One tunnel at a time: switching one on brings any other down first (avoids overlapping full-tunnel VPNs).
- Import `.conf` files from a file picker; they are installed root-owned (`0600`) into `/etc/wireguard`.
- Asks for your sudo password only when needed (kept in memory for 5 minutes, then forgotten).
- Opens as a fixed-size window, so tiling compositors such as niri float it automatically.

GTKGuard is an independent project and is not affiliated with the WireGuard project.

## Dependencies

Runtime: GTK4 (4.10+), libadwaita (1.6+), `sudo`, and `wireguard-tools` (`wg-quick`).
Build: Rust (edition 2024), `pkg-config`, `gtk4-devel`, `libadwaita-devel`.

The only crates are `gtk4` and `libadwaita`.

## Build and install

```sh
cargo build --release
./install.sh        # installs to ~/.local (binary, desktop entry, icon)
```

Make sure `~/.local/bin` is in your `PATH`, then launch GTKGuard from your launcher or run `gtkguard`.
Run it on the machine that has `wg-quick` (not inside a container).

## Security notes

- Configs are never kept in a user-writable location and run as root; they are installed to
  `/etc/wireguard` owned by root.
- Imports that contain `PreUp`/`PostUp`/`PreDown`/`PostDown` commands are refused, because `wg-quick`
  runs them as root.
- Config contents are never logged or shown in error messages.
- Tunnel names are validated (`[A-Za-z0-9_=+.-]`, max 15 characters) and commands run without a shell.
- Private keys in files you import may be world-readable where they came from; the app offers to delete
  the original after import.

## Limitations

- Only tunnels imported through the app are listed (listing `/etc/wireguard` needs root).
- No remove button yet: delete the name from `~/.config/gtkguard/tunnels` and the file from `/etc/wireguard`.


## License

Copyright (C) 2026 Andrew Taylor.

GTKGuard is free software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. See [LICENSE](LICENSE).
