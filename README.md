# ZAP DNS Blacklist

An Eggdrop IRC bot script that checks users joining channels against DNS blacklists (RBLs) and automatically bans them if listed. The configuration format is similar to [BOPM](https://wiki.blitzed.org/BOPM).

## Requirements

- Tcl >= 8.5
- [tcllib](http://www.tcl.tk/software/tcllib/) >= 1.10
- Eggdrop IRC bot

## Installation

1. Copy `zapdnsbl.tcl` and `zapdnsbl.ini` to `your_eggdrop/scripts/zapdnsbl/`
2. Add the following line to your `eggdrop.conf`:
   ```tcl
   source scripts/zapdnsbl/zapdnsbl.tcl
   ```
3. Reload (rehash) or restart your bot

## Configuration

Copy `zapdnsbl.ini.dist` to `zapdnsbl.ini` and customize as needed.

### Channel Settings

Enable or disable DNSBL checking per channel:
```
.chanset #channel +zapdnsbl    # Enable
.chanset #channel -zapdnsbl    # Disable
```

Set ban duration (in minutes, default is 120):
```
.chanset #channel zapdnsbl.bantime 60
```

Enable public command for users:
```
.chanset #channel +zapdnsbl.pubcmd
```

### Blacklist Configuration

Blacklists are configured in `zapdnsbl.ini`. Each blacklist is defined as a section with the format `[bl:hostname]`:

```ini
[bl:dnsbl.dronebl.org]
ban_unknown=false
default_ban_message=Your host is listed in the DroneBL (%reason%). http://dronebl.org/lookup_branded.do?ip=%ip% for info.
reply:3=IRC Drone
reply:5=Bottler
reply:8=SOCKS Proxy
reply:9=HTTP Proxy
```

Options:
- `ban_unknown` - Set to `true` to ban even when the reply code is not recognized
- `default_ban_message` - Ban message template. Supports `%reason%` and `%ip%` placeholders
- `reply:N` - Maps DNSBL reply code N to a human-readable reason

### WebIRC Support

For networks using WebIRC where the client IP is hex-encoded in the ident (e.g., `A1B2C3D4@gateway.example.com`), configure the `webirc_hosts` pattern in the `[global]` section:

```ini
[global]
webirc_hosts=.*(\.mibbit\.com|\.kiwiirc\.com)
```

## Commands

### DCC (Partyline)

| Command | Description |
|---------|-------------|
| `.zapblcheck <host>` | Check if a host/IP is listed in any configured DNSBL |
| `.zapblconfig bl list` | List all configured blacklists and their settings |

### Public Channel

Requires `+zapdnsbl.pubcmd` to be enabled on the channel.

| Command | Description |
|---------|-------------|
| `!zapblcheck <host>` | Check if a host/IP is listed in any configured DNSBL |

## Exemptions

Users with the following flags are exempt from DNSBL checks:
- `f` (friend)
- `o` (op)
- `v` (voice)

These can be global or channel-specific flags.

## Debugging

Debug output is sent to the console with flag `d`. To view debug messages:
```
.console +d
```

## License

GNU General Public License v2.0 - see [LICENSE](LICENSE) for details.
