# Security policy

## Authorized use only

This repository contains working exploit code and an intentionally vulnerable
application. It exists to help defenders validate exposure and confirm patches.

Use it only against systems you own or have explicit written permission to
test. Running the lab on an untrusted network or exposing it to the internet is
unsafe.

## Reporting a problem in this repository

If you find a bug in the PoC, lab, or documentation — for example, a case where
the patched build is reported as vulnerable — please open a private security
advisory:

<https://github.com/briskets/GHSA-xqc2-xf4c-x3h3-rce-poc/security/advisories/new>

Do not open a public issue for a false-negative or false-positive that could
mislead defenders.

## Reporting the underlying vulnerability

This repository is not the vendor. Report issues in React through the React
security advisory process and issues in Next.js through Vercel. The public
advisories are linked in the README.
