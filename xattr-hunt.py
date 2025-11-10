#!/usr/bin/env python3
# xattr-hunt.py — scan for long xattrs and identify content
#
# Usage:
#   sudo ./xattr-hunt.py / 1024
#   sudo ./xattr-hunt.py /var 512 --ns '^(user|security)\..*' --dump-dir /root/xattr_dumps
#   sudo ./xattr-hunt.py /home 256 --type f
#
# Output (TSV): bytes  file  attribute  mime  magic  sha256  note  dump_path

import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys

try:
    from typing import List, Optional, Tuple
except Exception:
    # Minimal fallback for very old envs
    Optional = None
    Tuple = None
    List = None

def detect_magic_and_mime(buf):
    """
    Return (mime, magic, note). Tries python-magic if available, else falls back to `file -b`.
    Adds quick signature notes (ELF, PE, ZIP, PDF, PNG, gzip).
    """
    note_parts = []
    if buf.startswith(b"\x7fELF"):
        note_parts.append("ELF binary")
    if buf[:2] == b"MZ":
        note_parts.append("PE (MZ)")
    if buf.startswith(b"PK\x03\x04"):
        note_parts.append("ZIP/Office/JAR")
    if buf.startswith(b"%PDF"):
        note_parts.append("PDF")
    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        note_parts.append("PNG image")
    if buf.startswith(b"\x1f\x8b"):
        note_parts.append("gzip")

    mime = "-"
    magic = "-"
    try:
        import magic as pymagic  # python-magic (optional)
        try:
            m = pymagic.from_buffer(buf, mime=True)
            if m:
                mime = m
        except Exception:
            pass
        try:
            m = pymagic.from_buffer(buf)
            if m:
                magic = m
        except Exception:
            pass
    except Exception:
        # Fallback to external `file`
        try:
            p = subprocess.Popen(["file", "-b", "--mime-type", "-"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            out, _ = p.communicate(buf)
            m = out.decode("utf-8", "replace").strip()
            if m:
                mime = m
        except Exception:
            pass
        try:
            p = subprocess.Popen(["file", "-b", "-"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            out, _ = p.communicate(buf)
            m = out.decode("utf-8", "replace").strip()
            if m:
                magic = m
        except Exception:
            pass

    return mime, magic, ", ".join(note_parts)

_B64_ALPHA = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

def maybe_decode_base64(buf):
    """Heuristic: if buffer looks like long base64, try to decode (returns bytes or None)."""
    sample = buf.strip()
    if len(sample) < 16:
        return None
    # If there are many non-base64 bytes, bail early
    head = sample[:4096]
    for ch in head:
        if ch not in _B64_ALPHA and ch not in (10, 13):  # allow \n \r
            return None
    try:
        compact = b"".join(sample.split())
        return base64.b64decode(compact, validate=True)
    except Exception:
        return None

def same_filesystem_only(top_dev, st):
    return st.st_dev == top_dev

def iter_paths(root, only_type, top_dev):
    """
    Yield paths under root, restricted to the same filesystem.
    only_type: None (mixed), 'f' (files), 'd' (dirs), 'all' (files+dirs+symlinks)
    """
    for current_root, dirs, files in os.walk(root, topdown=True, followlinks=False):
        kept_dirs = []
        for d in dirs:
            p = os.path.join(current_root, d)
            try:
                st = os.lstat(p)
            except Exception:
                continue
            if same_filesystem_only(top_dev, st):
                kept_dirs.append(d)
        dirs[:] = kept_dirs

        candidates = []
        if only_type in (None, "f", "all"):
            for f in files:
                candidates.append(os.path.join(current_root, f))
        if only_type in (None, "d", "all"):
            for d in dirs:
                candidates.append(os.path.join(current_root, d))
        if only_type in (None, "all"):
            candidates.append(current_root)

        for p in candidates:
            try:
                st = os.lstat(p)
            except Exception:
                continue
            if not same_filesystem_only(top_dev, st):
                continue
            yield p

def list_xattrs(path):
    try:
        return os.listxattr(path, follow_symlinks=False)
    except Exception:
        return []

def get_xattr(path, name):
    try:
        return os.getxattr(path, name, follow_symlinks=False)
    except Exception:
        return None

def safe_str(x):
    if isinstance(x, bytes):
        return(x.decode("utf-8", "backslashreplace"))
    return(str(x))

def main():
    ap = argparse.ArgumentParser(description="Scan filesystem for long xattrs and identify content (defensive).")
    ap.add_argument("start_path", help="Root path to scan (single filesystem, like find -xdev).")
    ap.add_argument("min_bytes", type=int, help="Report xattrs with value length >= this many bytes.")
    ap.add_argument("--ns", dest="ns_regex", default=".*",
                    help="Regex for attribute names (e.g., '^(user|security)\\..*'). Default: '.*'")
    ap.add_argument("--dump-dir", dest="dump_dir", default=None,
                    help="If set, dump decoded xattr blobs to this directory.")
    ap.add_argument("--type", dest="only_type", choices=["f", "d", "all"], default=None,
                    help="Limit object types: f=files only, d=dirs only, all=files+dirs+symlinks.")
    args = ap.parse_args()

    start = os.path.abspath(args.start_path)
    try:
        top_stat = os.lstat(start)
    except OSError:
        sys.stderr.write(f"ERROR: start path not found: {start}\n")
        sys.exit(1)

    if args.dump_dir:
        try:
            os.makedirs(args.dump_dir)
        except OSError:
            pass  # already exists or cannot create; will fail on write

    try:
        ns_re = re.compile(args.ns_regex.encode("utf-8"))
    except Exception as e:
        sys.stderr.write(f"ERROR: invalid regex for --ns: {e}\n")
        sys.exit(1)

    # Header
    sys.stdout.write("bytes\tfile\tattribute\tmime\tmagic\tsha256\tnote\tdump_path\n")

    for path in iter_paths(start, args.only_type, top_stat.st_dev):
        names = list_xattrs(path)
        if not names:
            continue
        for name in names:
            try:
                if not ns_re.match(name):
                    continue
            except Exception:
                # If name is not bytes on older py, ensure bytes
                try:
                    if not ns_re.match(name.encode("utf-8", "backslashreplace")):
                        continue
                except Exception:
                    continue

            val = get_xattr(path, name)
            if val is None:
                continue
            nbytes = len(val)
            if nbytes < args.min_bytes:
                continue

            mime, magic, note = detect_magic_and_mime(val)

            decoded = None
            if mime in ("text/plain", "application/octet-stream"):
                decoded = maybe_decode_base64(val)

            final_buf = decoded if decoded is not None else val
            if decoded is not None:
                mime2, magic2, _note2 = detect_magic_and_mime(decoded)
                if mime == "text/plain" and mime2 != "-":
                    mime, magic = mime2, magic2
                if note:
                    note = note + ", " + f"looks-like-base64→{mime2}"
                else:
                    note = f"looks-like-base64→{mime2}"

            sha = hashlib.sha256(final_buf).hexdigest()

            dump_path = ""
            if args.dump_dir:
                try:
                    attr_str = safe_str(name)
                    safe_attr = attr_str.replace("/", "_").replace(":", "_").replace(" ", "_").replace("\\", "_")
                    base = os.path.basename(path) or "inode"
                    dump_name = f"{sha[:12]}_{base}_{safe_attr}.bin"
                    dump_path = os.path.join(args.dump_dir, dump_name)
                    with open(dump_path, "wb") as f:
                        f.write(final_buf)
                except Exception as err:
                    sys.stderr.write(f"[!] Dump failed for {path}:{name} → {err}\n")
                    dump_path = ""

            attr_print = safe_str(name)
            sys.stdout.write(f"{nbytes}\t{path}\t{attr_print}\t{mime}\t{magic}\t{sha}\t{note}\t{dump_path}\n")

if __name__ == "__main__":
    main()
