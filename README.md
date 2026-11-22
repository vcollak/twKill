# twKill

Clear stuck TCP `TIME_WAIT` sockets on macOS **without rebooting**.

After roughly 49.7 days of uptime, macOS stops expiring `TIME_WAIT` sockets. They pile up until
the ephemeral port pool is exhausted, and new outbound connections start failing with:

```
nc: connectx to github.com port 443 (tcp) failed: Can't assign requested address
```

`twkill.py` frees those sockets by injecting forged TCP packets into the local network stack.
No kernel extension, no reboot.

## Symptoms

- Some websites or apps stop connecting while others still work.
- `nc -zv <host> 443`, `curl`, `git`, or local dev tools fail with `Can't assign requested address`
  (`EADDRNOTAVAIL`).
- Local services and MCP servers fail to start or connect.

## Diagnose

```sh
uptime                                     # more than ~50 days?
netstat -an -p tcp | grep -c TIME_WAIT     # tens of thousands, and never going down?
```

If both are true, you're hitting this bug. Normally `TIME_WAIT` lasts 2 × `net.inet.tcp.msl`
(30 s by default), so the count should stay in the hundreds.

## Why it happens

macOS's TCP stack keeps time in a 32-bit millisecond counter, which wraps after 2³² ms ≈ 49.7
days. After the wrap, `TIME_WAIT` timers never fire. Every connection your Mac closes first then
holds its local port forever.

IPv4 ephemeral ports come from **one shared pool** (49152–65535, about 16k ports by default). That
pool is shared across all local IPv4 addresses, including `127.0.0.1`. So heavy localhost traffic
(dev servers, databases) uses up the same ports that your connections to the internet need.

## Fix without rebooting

### 1. Get some headroom right away (optional)

Widen the ephemeral port range. This takes effect immediately and resets on reboot:

```sh
sudo sysctl -w net.inet.ip.portrange.first=10000 net.inet.ip.portrange.hifirst=10000
```

This only buys time. Sockets keep leaking, so the larger pool fills up too.

### 2. Clear the stuck sockets

```sh
python3 -I twkill.py --dry-run                               # list targets; sends nothing
sudo python3 -I twkill.py --match 127.0.0.1. --limit 50      # try a small batch first
sudo python3 -I twkill.py                                    # clear everything it can reach
```

Example output:

```
TIME_WAIT total: 31494; targeting 500
pass 1: targeted 500, cleared 236, remaining 264
pass 2: targeted 264, cleared 142, remaining 122
pass 3: targeted 122, cleared 66, remaining 56
...
sent 972 packets (0 errors); cleared 496/500 targeted; TIME_WAIT total now 31000 (was 31494)
```

Sockets keep leaking until you reboot (roughly 0.5–1 per second of normal use), so re-run it
periodically, for example once a day.

> `sudo` needs a real terminal to ask for your password. If you run commands through a tool that
> can't prompt (such as an AI coding assistant's shell), run these yourself in Terminal.

> `-I` runs Python in isolated mode, so it won't import stray modules from the current directory
> or from `PYTHON*` environment variables. That's a sensible habit for anything run as root.

## How it works

For each stuck socket (local **L**, remote **R**), the script forges a TCP **SYN** that appears to
come *from R to L* and sends it through a raw socket. The destination is a local address, so the
kernel loops the packet straight back into TCP input. The SYN carries a random sequence number:

| Sequence number vs. what the socket expects | What happens |
|---|---|
| **Below** (≈50% chance) | The stuck socket replies with a **challenge ACK** ([RFC 5961](https://www.rfc-editor.org/rfc/rfc5961)) that contains the exact sequence number it expects. The far end (the local kernel for `127.0.0.1`/`::1`, or the real remote server otherwise) doesn't recognize the connection and answers with a **RST** using that exact number. The RST is accepted and the socket is freed. |
| **Above** (≈50%) | The kernel takes a different path and the socket stays stuck, unharmed. |

After each pass the script checks `netstat` again and retries the sockets that are still there
with new random sequence numbers. Each pass clears about half of what's left. The default of 10
passes clears about 99.9%.

Live (`ESTABLISHED`) connections are never targeted. Only sockets in `TIME_WAIT` are.

## Options

| Flag | Default | Description |
|---|---|---|
| `--dry-run` | off | List targets and exit. Sends nothing and doesn't need root. |
| `--match TEXT` | all | Only target sockets whose local or remote endpoint contains `TEXT`, e.g. `127.0.0.1.`, `::1.`, `127.0.0.1.5273`. |
| `--limit N` | 0 (all) | Target at most `N` sockets. |
| `--passes N` | 10 | Number of retry rounds for sockets that didn't clear. |
| `--delay S` | 0.005 | Seconds between packets (~200/s). The kernel rate-limits the RSTs this relies on, so going much faster lowers the clear rate. |
| `--tries N` | 1 | SYNs per socket per pass, with sequence numbers spaced 2³⁰ apart. Keep it at 1: extra SYNs only use up the RST rate-limit budget. |
| `--method raw\|bpf` | `raw` | `bpf` (injecting on `lo0` through `/dev/bpf`) is kept for reference only: on Darwin 25 the packets never reach the TCP stack. |

## Limitations

- **macOS only.** Tested on macOS with Darwin 25.2.
- **Needs root**, because it uses raw sockets.
- **IPv6 link-local (`fe80::`) sockets are skipped.** They would need interface scope handling.
- **Some IPv6 sockets are skipped:** those whose remote address isn't one of this Mac's own
  addresses, such as connections from your global IPv6 address to internet servers. macOS IPv6 raw
  sockets can only send from a local source address. IPv6 loopback (`::1`) works.
- **Sockets to remote servers** only clear if the remote end answers the challenge ACK with a RST.
  Most servers do. For these, the challenge ACK is a real (tiny) packet sent over the network.
- **It's a workaround, not a cure.** Only a reboot (or an OS fix) stops the leak.

## What doesn't help

- Lowering `net.inet.tcp.msl`. The expiry logic itself is broken, so a shorter timeout changes
  nothing.
- Quitting apps, restarting Docker, toggling Wi-Fi, or bringing interfaces down and up. The sockets
  belong to the kernel, not to any process or interface.
- `tcpdrop`. macOS doesn't have it.

## License

[MIT](LICENSE) © 2026 Vlad Collak

## Disclaimer

This forges TCP packets into your own machine's network stack. It worked reliably in testing, but
use it at your own risk.
