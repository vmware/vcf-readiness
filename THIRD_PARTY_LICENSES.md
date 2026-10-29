# Third-Party Software Licenses & Attributions

This document details the licenses and notices for third-party software components and assets included in or distributed alongside the VCF / vSphere 9.1 HCI Readiness Assessment Tool (`vcf-readiness`).

The core application (`vcf_hci`) is licensed under the **CA, Inc. Software License Agreement** (see `LICENSE.md` and `NOTICE`). The third-party components listed below are distributed under their respective open-source licenses.

---

## Table of Contents

1. [VMware Clarity Design System (@cds/core)](#1-vmware-clarity-design-system-cdscore) — MIT
2. [PyInstaller Bootloader](#2-pyinstaller-bootloader) — GPL-2.0 with Bootloader Exception
3. [OpenSSL Library](#3-openssl-library) — Apache-2.0
4. [CPython Runtime](#4-cpython-runtime) — PSF-2.0
5. [libffi](#5-libffi) — MIT
6. [zlib Compression Library](#6-zlib-compression-library) — Zlib
7. [SQLite Database Engine](#7-sqlite-database-engine) — Public Domain
8. [Research Attributions](#8-research-attributions)

---

## 1. VMware Clarity Design System (@cds/core)

- **Component:** `@cds/core` (v5.7.0), pinned for reproducible offline assets.
- **License:** MIT, verified against the package metadata and release license.
- **Copyright:** Copyright (c) 2016-2021 VMware, Inc. All rights reserved.
- **Usage:** Embedded global CSS, dark-theme CSS and a selected subset of original SVG icon outlines. Semantic HTML and application JavaScript implement the interactions; Angular and Core custom-element runtimes are not bundled.
- **Source:** https://github.com/vmware-clarity/core/tree/v5.7.0
- **Full notice:** [licenses/clarity-core-MIT.txt](licenses/clarity-core-MIT.txt), included with distributions. Generated offline reports also include the notice in their source.

```text
MIT License

Copyright (c) 2016-2021 VMware, Inc.  All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The previous Apache-2.0 label for this component was incorrect. This corrects the attribution; it does not relicense the project.

---

## Standalone runtime inventory scope

The Python, OpenSSL, PyInstaller, libffi, zlib and SQLite versions below are historical reference versions, not a verified inventory of every current executable. Source execution uses the operator’s installed runtime; standalone releases require an artifact-specific inventory and retained notices. See [SBOM scope](docs/CUSTOMER_DELIVERABLE_SBOM.md). Optional vault AES support also requires the installed package’s own notices. Upstream VDT is operator-supplied and is not bundled by the scanner.

## 2. PyInstaller Bootloader

- **Component:** PyInstaller Bootloader (v6.11.0)
- **License:** GNU General Public License v2.0 with Bootloader Exception
- **Copyright:** Copyright (c) 2005-2024, PyInstaller Development Team
- **Usage:** Used solely to bootstrap self-contained platform executables (`bin/VCF-Readiness-Web-*`, `bin/vcf-assess*`). Not used when running the tool directly via Python source.
- **Source Code:** Available at https://github.com/pyinstaller/pyinstaller

### Special Exception Clause:

```
In addition to the permissions in the GNU General Public License, the
authors of PyInstaller give you additional permission to link the
output of PyInstaller with other files to produce an executable,
regardless of the license terms of these other files, and to distribute
that executable without being bound by the GNU GPL in full.

This exception does not however invalidate any other reasons why the
executable file might be covered by the GNU General Public License.
```

---

## 3. OpenSSL Library

- **Component:** OpenSSL (v3.0.13)
- **License:** Apache License, Version 2.0
- **Copyright:** Copyright (c) 1998-2024 The OpenSSL Project. All rights reserved.
- **Usage:** Bundled within compiled standalone platform binaries in `bin/` to provide TLS 1.2/1.3 communication with remote BMC endpoints over HTTPS.

---

## 4. CPython Runtime

- **Component:** Python Runtime (v3.11.9)
- **License:** Python Software Foundation License Version 2 (PSF-2.0)
- **Copyright:** Copyright (c) 2001-2024 Python Software Foundation. All rights reserved.
- **Usage:** Bundled inside compiled standalone platform binaries in `bin/` to allow execution on hosts without a pre-installed Python interpreter.

```
PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
--------------------------------------------
1. This LICENSE AGREEMENT is between the Python Software Foundation ("PSF"), and
the Individual or Organization ("Licensee") accessing and otherwise using this
software ("Python") in source or binary form and its associated documentation.

2. Subject to the terms and conditions of this License Agreement, PSF hereby
grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
analyze, test, perform and/or display publicly, prepare derivative works, distribute,
and otherwise use Python alone or in any derivative version, provided, however, that
PSF's License Agreement and PSF's notice of copyright, i.e., "Copyright (c) 2001-2024
Python Software Foundation; All Rights Reserved" are included in Python alone or in
any derivative version prepared by Licensee.
```

---

## 5. libffi

- **Component:** libffi (v3.4.4)
- **License:** MIT License
- **Copyright:** Copyright (c) 1996-2024 Anthony Green, Red Hat, Inc. and others.
- **Usage:** Foreign Function Interface library included with embedded CPython inside standalone platform binaries.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
```

---

## 6. zlib Compression Library

- **Component:** zlib (v1.3.1)
- **License:** Zlib License
- **Copyright:** Copyright (c) 1995-2024 Jean-loup Gailly and Mark Adler.
- **Usage:** Decompression and archive extraction in Python runtime and compiled binaries.

```
This software is provided 'as-is', without any express or implied warranty. In no
event will the authors be held liable for any damages arising from the use of
this software.

Permission is granted to anyone to use this software for any purpose, including
commercial applications, and to alter it and redistribute it freely, subject to
the following restrictions:

1. The origin of this software must not be misrepresented; you must not claim
   that you wrote the original software.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
```

---

## 7. SQLite Database Engine

- **Component:** SQLite (v3.45.1)
- **License:** Public Domain / SQLite Blessing
- **Usage:** SQLite is available through Python’s `sqlite3` module for catalog/tooling use and may be included with standalone Python runtimes. The credential vault is an encrypted JSON envelope, not a SQLite database.

```
The author disclaims copyright to this source code. In place of a legal notice,
here is a blessing:

   May you do good and not evil.
   May you find forgiveness for yourself and forgive others.
   May you share freely, never taking more than you give.
```

---

## 8. Research Attributions

- **Network Switch Buffer Intelligence & ASIC Telemetry:** Switch buffer classifications, VOQ buffer algorithms, and switch ASIC architecture cross-references are derived from research and documentation published by Michael Buraglio and Jim Warner.
