#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Vlad Collak
"""
twkill.py - clear stuck TCP TIME_WAIT sockets on macOS without rebooting.

THE PROBLEM
-----------
After roughly 49.7 days of uptime (2^32 milliseconds), macOS's TCP stack stops expiring
sockets in the TIME_WAIT state. TIME_WAIT normally lasts 2 x net.inet.tcp.msl (30 s by
default); once the bug hits, every connection your Mac closes first sits in TIME_WAIT
forever, permanently holding its local ephemeral port.

Ephemeral ports for IPv4 come from one shared pool (49152-65535 by default, ~16k ports)
that is shared across ALL local IPv4 addresses, including 127.0.0.1. When the leaked
sockets fill that pool, new outbound connections fail with:

    connectx ... failed: Can't assign requested address   (EADDRNOTAVAIL)

Symptoms: some websites/apps stop connecting while others still work, MCP servers fail
to start, `nc -zv github.com 443` fails. Diagnose with:

    uptime                                      # > ~50 days?
    netstat -an -p tcp | grep -c TIME_WAIT      # tens of thousands, and never decreasing?

Things that do NOT help: lowering net.inet.tcp.msl (the expiry logic itself is broken),
quitting apps, restarting Docker, toggling Wi-Fi (the sockets are owned by the kernel,
not by any process or interface). macOS has no `tcpdrop`. A reboot fixes it.

Stop-gap without clearing anything: widen the ephemeral port range (resets on reboot):

    sudo sysctl -w net.inet.ip.portrange.first=10000 net.inet.ip.portrange.hifirst=10000

HOW THIS SCRIPT CLEARS THEM
---------------------------
For each stuck socket (local L, remote R) we forge a TCP SYN that appears to come FROM R
TO L, and hand it to the kernel through a raw socket. Because the destination is a local
address, the packet is looped back internally to TCP input. What happens next depends on
the random sequence number we put in the SYN, relative to what the socket expects
(rcv_nxt):

  * seq "below" rcv_nxt (about 50% chance): the stuck socket replies with a "challenge
    ACK" (RFC 5961) addressed to R, carrying the exact sequence number it expects.
      - If R is local (127.0.0.1, ::1): the kernel sees an ACK for a connection that
        does not exist and answers with a RST using that exact sequence number. A RST
        with the exact sequence number is accepted, and the TIME_WAIT socket is freed.
      - If R is remote (e.g. a Cloudflare IP): the challenge ACK really goes out over the
        network. The remote server doesn't know this connection anymore and replies RST,
        which frees the socket the same way.
  * seq "above" rcv_nxt (other ~50%): the kernel takes a different path and the socket
    stays stuck, but unharmed. A later attempt with a new random seq can still clear it.

So each pass clears about half of the remaining targets; the script re-checks netstat
after each pass and retries the leftovers (default 10 passes -> ~99.9% cleared).

Verified 2026-11-22 on macOS / Darwin 25.2: loopback (IPv4 and ::1) and external IPv4
sockets clear at ~50% per pass. Live (ESTABLISHED) connections are never targeted.

LIMITATIONS
-----------
  * IPv6 link-local (fe80::...) sockets are skipped (they need interface scope handling).
  * IPv6 sockets whose remote address is not one of this Mac's own addresses (e.g. your
    global (2xxx:...) address talking to an internet server) are skipped: an IPv6 raw socket
    can only send from a local source address, so the SYN can't be forged.
  * Sockets keep leaking (~0.5-1 per second of normal use) until you reboot, so re-run this
    periodically.
  * --method bpf (injecting on lo0 via /dev/bpf) is kept for reference only: on Darwin 25
    the packets are accepted by BPF but never reach the TCP stack, so it clears nothing.

USAGE (needs root; -I keeps Python from importing stray modules from the current
directory or PYTHON* environment variables, which matters when running as root)
-----
  python3 -I ~/twkill.py --dry-run                               # list targets, send nothing
  sudo python3 -I ~/twkill.py --match 127.0.0.1.5273 --limit 1   # test on ONE socket
  sudo python3 -I ~/twkill.py --match 127.0.0.1. --limit 500     # a small batch
  sudo python3 -I ~/twkill.py                                    # everything it can reach

Output: one line per pass ("targeted / cleared / remaining"), then a summary with the
total TIME_WAIT count before and after.
"""
import argparse, fcntl, os, random, socket, struct, subprocess, sys, time

# ioctl request to attach a BPF device to a network interface: _IOW('B', 108, struct ifreq).
# Only used by the (non-working) --method bpf.
BIOCSETIF = 0x8020426C


# ----------------------------------------------------------------------------------------
# Finding stuck sockets
# ----------------------------------------------------------------------------------------

def parse_endpoint(s, v6):
    """Split a netstat endpoint like '127.0.0.1.54493' or '::1.5432' into (addr, port).

    macOS netstat separates the port with a '.', even for IPv6, so split on the last dot.
    IPv6 zone suffixes ('fe80::1%lo0') are stripped.
    """
    addr, port = s.rsplit(".", 1)
    if v6:
        addr = addr.split("%", 1)[0]
    return addr, int(port)


def time_wait_sockets():
    """Return every TIME_WAIT socket we know how to target.

    Each entry is a tuple:
        (is_ipv6, local_text, remote_text, (local_addr, local_port), (remote_addr, remote_port))
    The *_text fields are the raw netstat strings; they are used as a stable key to check
    whether a socket is still present after a pass.
    """
    out = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True).stdout
    res = []
    for line in out.splitlines():
        f = line.split()
        # Columns: Proto Recv-Q Send-Q Local Foreign State
        if len(f) < 6 or f[-1] != "TIME_WAIT" or not f[0].startswith("tcp"):
            continue
        v6 = f[0] == "tcp6"
        try:
            l = parse_endpoint(f[3], v6)
            r = parse_endpoint(f[4], v6)
            # netstat truncates long IPv6 addresses; validate so we never send to garbage.
            socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET, l[0])
            socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET, r[0])
        except (ValueError, OSError):
            continue
        if v6 and (l[0].lower().startswith("fe80") or r[0].lower().startswith("fe80")):
            continue  # link-local: would need the interface scope id; not supported
        res.append((v6, f[3], f[4], l, r))
    return res


# ----------------------------------------------------------------------------------------
# Building the forged SYN
# ----------------------------------------------------------------------------------------

def csum(data):
    """Standard Internet checksum (RFC 1071): ones'-complement sum of 16-bit words."""
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_syn(src, dst, sport, dport, seq, v6):
    """Build a 20-byte TCP header with only the SYN flag set and a valid checksum.

    src/dst are packed addresses (4 or 16 bytes); they're needed for the checksum's
    pseudo-header even though they aren't part of the TCP header itself.
    """
    # sport, dport, seq, ack=0, data offset=5 words, flags=SYN, window, checksum=0, urg=0
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 65535, 0, 0)
    if v6:
        # IPv6 pseudo-header: src, dst, upper-layer length (32 bit), 3 zero bytes, next header
        pseudo = src + dst + struct.pack("!IxxxB", len(hdr), socket.IPPROTO_TCP)
    else:
        # IPv4 pseudo-header: src, dst, zero byte, protocol, TCP length
        pseudo = src + dst + struct.pack("!xBH", socket.IPPROTO_TCP, len(hdr))
    c = csum(pseudo + hdr)
    return hdr[:16] + struct.pack("!H", c) + hdr[18:]


def build_packet(v6, remote, local, seq):
    """Build a full forged packet: remote -> local, SYN with the given sequence number.

    Returns  [4-byte DLT_NULL header][IP header][TCP header].
    The DLT_NULL header is what BPF on lo0 expects; the raw-socket senders slice it off:
      - IPv4 raw socket gets [IP header][TCP header]   (pkt[4:])
      - IPv6 raw socket gets [TCP header] only         (pkt[44:]); the kernel adds IPv6.
    """
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    src = socket.inet_pton(fam, remote[0])   # forged source = the socket's remote end
    dst = socket.inet_pton(fam, local[0])    # destination   = the socket's local end
    tcp = tcp_syn(src, dst, remote[1], local[1], seq, v6)
    if v6:
        # version 6 | traffic class 0 | flow label 0, payload length, next header, hop limit
        ip = struct.pack("!IHBB", 6 << 28, len(tcp), socket.IPPROTO_TCP, 64) + src + dst
        af = socket.AF_INET6  # 30 on macOS
    else:
        # version 4 / IHL 5, TOS, total length, random IP ID, flags/frag 0, TTL 64, TCP,
        # checksum (filled in below), src, dst
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), random.randint(0, 0xFFFF),
                         0, 64, socket.IPPROTO_TCP, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        af = socket.AF_INET
    return struct.pack("=I", af) + ip + tcp  # DLT_NULL: address family in host byte order


def open_bpf_lo0():
    """Open a BPF device attached to lo0 (--method bpf only; does not work on Darwin 25)."""
    fd = None
    # Newer macOS has a cloning /dev/bpf; older versions need a free /dev/bpfN.
    for path in ["/dev/bpf"] + ["/dev/bpf%d" % i for i in range(256)]:
        try:
            fd = os.open(path, os.O_RDWR)
            break
        except OSError:
            continue
    if fd is None:
        sys.exit("could not open a /dev/bpf device (are you root?)")
    fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", b"lo0"))  # struct ifreq: name + padding
    return fd


# ----------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Clear stuck TCP TIME_WAIT sockets on macOS by injecting forged SYNs. "
                    "See the docstring at the top of this file for how it works.")
    ap.add_argument("--dry-run", action="store_true",
                    help="list the targets and exit without sending anything (no root needed)")
    ap.add_argument("--match",
                    help="only sockets whose local or remote endpoint contains this text, "
                         "e.g. '127.0.0.1.', '::1.', '192.168.1.10.', '127.0.0.1.5273'")
    ap.add_argument("--limit", type=int, default=0, help="max sockets to target (0 = all)")
    ap.add_argument("--method", choices=["bpf", "raw"], default="raw",
                    help="raw (default, works): raw IPv4/IPv6 sockets; "
                         "bpf: inject on lo0 (reference only, does not work on Darwin 25)")
    ap.add_argument("--delay", type=float, default=0.005,
                    help="seconds between packets (default 0.005 = ~200/s); the kernel "
                         "rate-limits the RSTs this relies on, so going much faster lowers "
                         "the clear rate")
    ap.add_argument("--passes", type=int, default=10,
                    help="rounds: after each, sockets still present are retried with a new "
                         "random sequence number (~50%% clear per round)")
    ap.add_argument("--tries", type=int, default=1,
                    help="SYNs per socket per pass, sequence numbers spaced 2^30 apart. 1 is "
                         "best: extra SYNs only spend the kernel's RST rate-limit budget")
    a = ap.parse_args()

    # --- choose targets -----------------------------------------------------------------
    socks = time_wait_sockets()
    if a.match:
        socks = [s for s in socks if a.match in s[1] or a.match in s[2]]
    if a.limit:
        socks = socks[: a.limit]
    total_before = len(time_wait_sockets())
    # Note: this "targeting" count is before IPv6 sockets we can't forge are dropped (below).
    print(f"TIME_WAIT total: {total_before}; targeting {len(socks)}")
    if a.dry_run:
        for s in socks[:20]:
            print(f"  {'tcp6' if s[0] else 'tcp4'} {s[1]} -> {s[2]}")
        if len(socks) > 20:
            print(f"  ... and {len(socks) - 20} more")
        return
    if os.geteuid() != 0:
        sys.exit("must run as root (sudo)")

    # --- set up senders -----------------------------------------------------------------
    # IPv6: there is no IP_HDRINCL for IPv6 on macOS, so the kernel always writes the IPv6
    # header and picks the source address from the socket's bound address. To forge a
    # packet "from" the remote end we bind a raw socket to the remote address, which only
    # succeeds if that address is one of ours (e.g. ::1). One socket per remote address.
    v6socks = {}  # remote IPv6 addr -> bound raw socket, or None if it can't be bound

    def v6sock(addr):
        if addr not in v6socks:
            try:
                s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s6.bind((addr, 0))
                v6socks[addr] = s6
            except OSError:
                v6socks[addr] = None
        return v6socks[addr]

    if a.method == "raw":
        # Drop IPv6 targets whose remote address we can't send from (see LIMITATIONS).
        socks = [s for s in socks if not s[0] or v6sock(s[4][0]) is not None]
        # IPv4: IP_HDRINCL lets us supply the whole IP header, including a forged source.
        rs_ = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        rs_.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        fd = open_bpf_lo0()
    sent = errors = 0

    def send_round(targets):
        """Send one forged SYN (or --tries SYNs) to every target socket."""
        nonlocal sent, errors
        for v6, ls, rs, local, remote in targets:
            # Random seq each round: ~50% chance it's "below" rcv_nxt, which is the case
            # that triggers the challenge ACK -> RST sequence that frees the socket.
            base = random.getrandbits(32)
            for k in range(a.tries):
                pkt = build_packet(v6, remote, local, (base + k * (1 << 30)) & 0xFFFFFFFF)
                try:
                    if a.method == "raw" and v6:
                        # Kernel builds the IPv6 header; we send only the TCP segment, whose
                        # checksum was computed above with the same src/dst addresses.
                        v6sock(remote[0]).sendto(pkt[4 + 40:], (local[0], 0))
                    elif a.method == "raw":
                        ip = bytearray(pkt[4:])
                        # macOS quirk (historic BSD behavior): with IP_HDRINCL, ip_len and
                        # ip_off must be in HOST byte order, not network byte order.
                        ip[2:4] = struct.pack("=H", len(ip)); ip[6:8] = struct.pack("=H", 0)
                        rs_.sendto(bytes(ip), (local[0], 0))
                    else:
                        os.write(fd, pkt)
                    sent += 1
                except OSError as e:
                    errors += 1
                    if errors <= 3:  # don't flood the terminal if something is broken
                        print(f"write error for {ls} -> {rs}: {e}")
                if a.delay:
                    time.sleep(a.delay)

    # --- run passes until everything is cleared or we run out of passes --------------------
    remaining = list(socks)
    for n in range(1, a.passes + 1):
        if not remaining:
            break
        send_round(remaining)
        time.sleep(1)  # let the challenge ACKs / RSTs (including remote replies) arrive
        keys = {(s[1], s[2]) for s in time_wait_sockets()}
        still = [s for s in remaining if (s[1], s[2]) in keys]
        print(f"pass {n}: targeted {len(remaining)}, cleared {len(remaining) - len(still)}, "
              f"remaining {len(still)}")
        remaining = still

    # --- clean up and report --------------------------------------------------------------
    if a.method == "raw":
        rs_.close()
        for s6 in v6socks.values():
            s6 and s6.close()
    else:
        os.close(fd)

    after = len(time_wait_sockets())
    print(f"sent {sent} packets ({errors} errors); cleared {len(socks) - len(remaining)}/{len(socks)} "
          f"targeted; TIME_WAIT total now {after} (was {total_before})")


if __name__ == "__main__":
    main()
