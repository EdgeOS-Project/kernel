# Vendored zlib

`upstream/` is the unmodified zlib 1.3.2 source directory from FreeBSD commit
`bb5c77e9d281d6def6835d48249898764bc6a5fe`. It is distributed under the
zlib license in `upstream/LICENSE`.

The small translation units beside this file select the decompression-only
configuration used by the architecture-neutral EdgeOS gzip adapter. Keeping
the selected source in the main repository makes initramfs decompression
independent of the `third_party_kernel` reference tree.
