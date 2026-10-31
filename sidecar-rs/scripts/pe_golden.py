#!/usr/bin/env python3
"""Build golden loader-view images for the sidecar's PE relocation test.

For each PE image given (files, or directories of them), pefile maps it at
bases other than its preferred one -- headers and sections at their RVAs, base
relocations applied -- and writes OUTDIR/<name> and
OUTDIR/<name>.mapped-<hexbase>. Then

    LRNG_PE_SAMPLES=OUTDIR cargo test matches_pefile_on_real_images

checks that the sidecar's PE reader reproduces those bytes. pefile
(https://github.com/erocarrera/pefile) is an independent implementation, so
this guards against the reader and its own tests sharing a misreading.
"""
import os
import shutil
import sys

import pefile


def bases(pe):
    if pe.OPTIONAL_HEADER.Magic == 0x10B:  # PE32: stay below 4 GiB
        return [0x6A230000, 0x01000000]
    return [0x7FF612340000, 0x0000020012340000]


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: pe_golden.py OUTDIR IMAGE_OR_DIR...")
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    n = 0
    for arg in sys.argv[2:]:
        paths = [os.path.join(arg, f) for f in sorted(os.listdir(arg))] if os.path.isdir(arg) else [arg]
        for p in paths:
            try:
                pe = pefile.PE(p, fast_load=True)
            except pefile.PEFormatError:
                continue
            name = os.path.basename(p)
            shutil.copyfile(p, os.path.join(out, name))
            # Named, non-forwarded exports as "rva name" lines.
            # pefile stops at 8192 exports by default; match the reader's cap.
            ex = pefile.PE(p, fast_load=True, max_symbol_exports=1 << 16)
            ex.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            with open(os.path.join(out, f"{name}.exports"), "w") as f:
                for s in getattr(getattr(ex, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
                    if s.name and not s.forwarder:
                        f.write(f"{s.address:x} {s.name.decode('ascii', 'replace')}\n")
            for base in bases(pe):
                img = pefile.PE(p, fast_load=True).get_memory_mapped_image(ImageBase=base)
                with open(os.path.join(out, f"{name}.mapped-{base:x}"), "wb") as f:
                    f.write(img)
                n += 1
    print(f"wrote {n} golden image(s) to {out}")


if __name__ == "__main__":
    main()
