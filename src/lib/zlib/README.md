# Vendored zlib

`upstream/` contains the unmodified zlib 1.3.2 source files needed by EdgeOS,
imported from FreeBSD commit `bb5c77e9d281d6def6835d48249898764bc6a5fe`.
They are distributed under the zlib license in `upstream/LICENSE`.

The small translation units beside this file select the decompression-only
configuration used by the architecture-neutral EdgeOS gzip adapter. The
selected source is self-contained in the kernel repository.
