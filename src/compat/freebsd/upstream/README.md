# Vendored FreeBSD Driver Sources

This directory contains the exact, unmodified source closure selected by the
BSD Driver Bridge manifests in `config/bsd_drivers/manifests`.

The manifests record the original repository, pinned FreeBSD commit, selected
files, accepted license alternatives, file counts, and content digests. The
build and verification tools consume this directory directly. The
`third_party_kernel` tree is only an update and review reference and is not
required to build EdgeOS.

To update a package, copy only its reviewed dependency closure from the pinned
upstream commit, update its manifest lock, run the source and license checks,
and validate both architectures.
