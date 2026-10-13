<div align="center">
  <img src="./banner.svg" alt="smb-audit" width="800">
</div>

# smb-audit

> Red team post-exploitation tool — authorized use only.

```bash
python smb_audit.py --help
```

> **Authorized security testing only.**

## SMBv1 probe evidence

The raw SMBv1 check sends a negotiation request to the specified host on TCP
port 445 (or the port passed to its Python API), then reads one complete
NetBIOS session-service response, capped at 4 KiB. `smbv1: true` means the
server accepted one of the offered SMB1 dialects. `smbv1: false` means the
server returned a valid SMB negotiation error or explicitly declined the
dialect list. `smbv1: null` means the response was incomplete, malformed,
oversized, or unavailable; it is not evidence that SMBv1 is disabled.

SMBv1 negotiation alone does not establish that a host is vulnerable to
EternalBlue, WannaCry, or any other specific vulnerability.

## Scope and limitations

The SMBv1 probe itself does not authenticate, exploit SMB, enumerate shares,
read file contents, or modify shares. The complete tool has broader behavior:
when Impacket is installed it attempts an anonymous login, optionally logs in
with the supplied `--user` and `--password`, lists share metadata, and requests
directory entries from each share. These checks are not passive. Run the tool
only against explicitly authorized hosts; it does not enforce a target allowlist
or otherwise verify authorization.

**Omar Khalid** — [omareldemery.com](https://omareldemery.com)
