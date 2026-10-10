# Python for VX / Rez

VX maintains CPython 3.7.9 runtime assets and real Rez package definitions in
this repository. Each variant includes the interpreter, standard library,
development headers, link libraries, original build metadata, build objects
and bundled notices. Native Rez package releases and installed VX consumer
acceptance are separate delivery gates.

| Variant | Archive release | Historical build source | Runtime requirement |
| --- | --- | --- | --- |
| Windows x64 | `20200822` | `3aa43064f27717808f0f2fbfc00a14ed91a00de2` | Bundled `vcruntime140.dll` |
| Linux x64 | `20200822` | `3aa43064f27717808f0f2fbfc00a14ed91a00de2` | glibc 2.17 or newer |
| macOS x64 | `20200823` | `51a442d1ce41298e3007daf1c8ff334ea91576a2` | macOS 10.9 or newer |

The macOS archive comes from the following day's release to include its
`libintl.dylib` dependency correction. The bundled intake metadata preserves
its separate build revision and archive digest. ARM variants have no audited
archive in these releases and are explicitly unsupported.

## Package layout and environment

`package.py` declares the actual Rez variants and modifies only `PATH`.
It adds `payload/install` and `payload/install/bin`; it sets no `PYTHONHOME` or
`PYTHONPATH`. The full upstream `python` directory is preserved beneath
`payload`. On Unix, the declared archive mapping also copies the real
`python3.7m` executable to `install/bin/python`, so the package exposes the same
`python` command on each supported platform.

| Component | Windows | Linux and macOS |
| --- | --- | --- |
| Interpreter | `payload/install/python.exe` | `payload/install/bin/python` |
| Standard library | `payload/install/Lib` | `payload/install/lib/python3.7` |
| C API headers | `payload/install/include` | `payload/install/include/python3.7m` |
| Link library | `payload/install/libs/python37.lib` | `payload/install/lib/libpython3.7m.a` |
| Upstream build description | `payload/PYTHON.json` | `payload/PYTHON.json` |
| Original dependency notices | `payload/licenses` | `payload/licenses` |

The shared [package tooling](https://github.com/vx-org/vx-rez-packages) validates
and extracts pinned archives, copies the hash-verified `package.py` unchanged,
runs native smoke commands, and produces deterministic Rez bundles and a
version index. `rez-next-runtime` owns package reading, dependency solving,
variant selection and environment commands; `vx-rez-adapter` exposes that
contract to consumers. VX acquisition, caching, command dispatch and offline
execution must consume the resulting index and packages through that boundary.

## Historical source intake

The first intake tag is `python-3.7.9-pbs-20200823`. Its archive set consists of
three unchanged upstream runtimes, 22 pinned component source archives, and two
exact historical PBS build recipe archives: **27 archives, 216,836,724 bytes**.
The build recipe archives retain the scripts and patches for the two original
build revisions. The intake also records the required GPL and LGPL component
notices from the gettext source archive.

`prepare_release_assets.py` verifies all 27 local files again and copies them
into a flat source directory for publication. It requires all 22 component
sources and the ten audited gettext notices to have passed retention. Existing
files are reused only after fixed size and SHA256 verification. The helper
performs no network acquisition or runtime execution.

Its `intake-assets.json` records actual upstream acquisition URLs, byte pins and
the distinction between computed intake digests and historical recipe pins.
Temporary redirect query parameters are omitted from public receipts; original
acquisition receipts remain local. It also creates
`recipe.organization-proposed.json`, whose target URLs and `release_assets`
point to the organization intake tag. The current recipe was promoted after
the public release became immutable and all 60 assets (217,117,323 bytes) were
downloaded again and verified by name, size and SHA256. The public verification
receipt is retained in `public-intake-verification.json`.

The published intake metadata is bound to source commit
`1ffcf102a7976b1d96a595d01767eeeb79e35829`. Run
`verify_release_readback.py --root` against that frozen checkout when checking
this historical release; the promoted recipe uses the verified organization
URLs. For a new intake, promote its generated recipe only after the same public
immutability and byte verification gates pass.

`prepare_recipe.py` performs the initial audit bootstrap. After regenerating a
recipe, complete source retention again and run `prepare_release_assets.py` as
the final preparation step. This step always regenerates the sanitized public
receipt from private acquisition evidence before producing the proposed
organization recipe.

An intake release closes the historical acquisition and source-retention gate.
Matching-platform native smoke tests, published Rez bundles and the package
index still require their own release validation. Installed VX consumer
acceptance remains pending until the actual client downloads organization
assets with an empty cache and successfully resolves and runs this package.

## Native validation

The native smoke checks the real interpreter, binary extension modules, bundled
standard library, headers and link libraries, then creates and executes a fresh
virtual environment. A separate VX consumer acceptance run must still verify
fresh organization acquisition, version resolution, environment activation,
native extension compilation and offline reuse.

The native smoke uses the packaged interpreter directly, without a system
Python installation. The full development files support native extension
builds; installed-client acceptance must compile and execute a real extension
against the acquired interpreter and then repeat from the offline cache.

## Provenance and licenses

Repository scripts and package definitions use the MIT license. Retained runtime
and source archives keep their own component licenses and notices.

The original runtime digests were computed when the files were imported over official
GitHub HTTPS. Historical release asset IDs and sizes were checked. Those
releases expose no publisher checksum or signature, so these hashes are an
explicit intake trust bootstrap. They must not be described as upstream signed
digests. Repackaged artifact hashes are a separate integrity record.

The component source digests come from the fixed historical PBS download
manifests. The Git source archive digests were computed after HTTPS acquisition
of the pinned build revisions. Each digest's origin remains explicit in the
intake and source-retention records; repackaged bundle digests are recorded
separately.

Linux includes GPL readline and Berkeley DB; macOS includes Berkeley DB and
gettext libraries. `source-closure.json` records the pinned source corpus.
The matching source archives, build scripts, patches and component notices
must accompany the retained runtimes. Bundled metadata records the observed
publication state at build time; later immutable release readback supplies a
separate publication receipt.

The retained Berkeley DB 6.0.19 source `LICENSE` contains Oracle redistribution
clauses, including a complete-source condition, followed by Berkeley, Harvard
and ASM notices. It contains no Affero text. Its original bytes, digest and
comparison with the runtime's bundled license copies are recorded in
`metadata/bdb-license-provenance.json`.

The pinned PBS documentation identifies 6.0.19 as Sleepycat-licensed.
[Oracle's 6.0 announcement](https://oss.oracle.com/pipermail/bdb/2013-June/000056.html)
describes AGPL terms, while its
[6.0.20 changelog](https://download.oracle.com/otndocs/products/berkeleydb/html/changelog_6_0.html)
records an update of the `LICENSE` file to AGPL. These differing publisher
statements and the literal 6.0.19 license remain separate provenance evidence.
Their legal interpretation is unresolved by this artifact audit; byte
integrity, complete source retention and native execution are tracked
independently.
