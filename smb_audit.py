#!/usr/bin/env python3
"""
SMB Audit — SMB/CIFS Security Auditing Tool
Checks for null sessions, SMBv1, exposed shares, and EternalBlue vulnerability indicators.
Requires impacket: pip install impacket
Author: Omar Khalid (amooryx) | github.com/amooryx/smb-audit
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor

try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

# ─── Raw SMB1 negotiation (no impacket needed) ────────────────────────────────
def check_smbv1_raw(host: str, port: int = 445, timeout: float = 8) -> bool:
    """Check if SMBv1 is offered without impacket (raw negotiate)."""
    smb1_negotiate = (
        b"\x00\x00\x00\x85"       # NetBIOS length
        b"\xff\x53\x4d\x42"       # SMB header: \xFF SMB
        b"\x72"                    # SMB_COM_NEGOTIATE
        b"\x00\x00\x00\x00"       # NT Status
        b"\x18\x53\xc8\x00"       # Flags
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xff\xff\xff\xfe\x00\x00\x00\x00"
        b"\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b"
        b"\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"
        b"\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
        b"\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20"
        b"\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e"
        b"\x31\x61\x00"
        b"\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"
        b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
    )
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(smb1_negotiate)
        resp = sock.recv(256)
        sock.close()
        if len(resp) > 4 and resp[4:8] == b"\xff\x53\x4d\x42":
            dialect_idx = struct.unpack_from("<H", resp, 37)[0] if len(resp) > 39 else 0
            return dialect_idx in (0, 1, 2, 3, 4)  # SMBv1 dialects accepted
    except Exception:
        pass
    return False

def check_null_session(host: str) -> dict:
    """Try anonymous null session (no creds)."""
    if not HAS_IMPACKET:
        return {"null_session": "unknown", "note": "impacket required"}
    try:
        conn = SMBConnection(host, host, timeout=10)
        conn.login("", "")  # null creds
        shares = conn.listShares()
        share_list = [s["shi1_netname"].rstrip("\x00") for s in shares]
        conn.logoff()
        return {"null_session": True, "shares": share_list}
    except SessionError as e:
        return {"null_session": False, "error": str(e)}
    except Exception as e:
        return {"null_session": "error", "error": str(e)}

def check_shares(host: str, user: str = "", password: str = "") -> list[dict]:
    """List shares and try to access each one."""
    if not HAS_IMPACKET:
        return []
    try:
        conn = SMBConnection(host, host, timeout=10)
        conn.login(user, password)
        shares = conn.listShares()
        results = []
        for s in shares:
            name = s["shi1_netname"].rstrip("\x00")
            try:
                conn.listPath(name, "*")
                accessible = True
            except Exception:
                accessible = False
            results.append({"name": name, "type": s["shi1_type"], "accessible": accessible,
                            "remark": s["shi1_remark"].rstrip("\x00")})
        conn.logoff()
        return results
    except Exception as e:
        return [{"error": str(e)}]

def scan_host(host: str, user: str, password: str) -> dict:
    result = {"host": host}
    result["port_445_open"] = False
    try:
        s = socket.create_connection((host, 445), timeout=5)
        s.close()
        result["port_445_open"] = True
    except Exception:
        return result

    result["smbv1"]       = check_smbv1_raw(host)
    result["null_session"] = check_null_session(host)
    result["shares"]       = check_shares(host, user, password)

    # Flag critical issues
    result["findings"] = []
    if result["smbv1"]:
        result["findings"].append({"severity": "High", "issue": "SMBv1 enabled — vulnerable to EternalBlue/WannaCry"})
    ns = result["null_session"]
    if isinstance(ns, dict) and ns.get("null_session"):
        result["findings"].append({"severity": "High", "issue": f"Null session allowed — shares visible: {ns.get('shares', [])}"})
    for share in result.get("shares", []):
        if share.get("accessible") and share.get("name", "").upper() not in ("IPC$",):
            result["findings"].append({"severity": "Medium", "issue": f"Share accessible: {share['name']}"})

    return result

def main():
    parser = argparse.ArgumentParser(
        description="SMB Audit — SMB Security Audit (Authorized use only)",
    )
    parser.add_argument("hosts",       nargs="+", help="Target hosts or IPs")
    parser.add_argument("--user",      default="",  help="Username (blank for null session)")
    parser.add_argument("--password",  default="",  help="Password")
    parser.add_argument("--threads",   type=int, default=20)
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    print(f"[*] SMB audit: {len(args.hosts)} hosts")
    print("[!] AUTHORIZED USE ONLY")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(scan_host, h, args.user, args.password): h for h in args.hosts}
        for fut in futures:
            r = fut.result()
            results.append(r)
            if r.get("port_445_open"):
                for f in r.get("findings", []):
                    print(f"  [{f['severity']}] {r['host']}: {f['issue']}")
            else:
                print(f"  [--] {r['host']}: port 445 closed")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
