#!/usr/bin/env python3
"""ctest entry point: replay recorded MMU scenarios on bbn-run and compare with the golden
transcripts (originally produced by QEMU and verified identical to bareboxn's).

Exit status 77 (ctest SKIP) when the optional Python dependencies are missing."""
import os, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
try:
    import keystone  # noqa: F401
except ImportError:
    print("SKIP: keystone-engine not installed")
    sys.exit(77)
build = sys.argv[1] if len(sys.argv) > 1 else "build"
golden = os.path.join(os.path.dirname(os.path.dirname(here)), "tests", "mmu_golden")
seeds = sorted(int(f[5:-4]) for f in os.listdir(golden) if f.startswith("seed_"))
rc = subprocess.call([sys.executable, os.path.join(here, "mmu_diff.py"), "--build-dir", build, "--check", golden,
                      "--seeds", "%d-%d" % (seeds[0], seeds[-1])])
sys.exit(rc)
