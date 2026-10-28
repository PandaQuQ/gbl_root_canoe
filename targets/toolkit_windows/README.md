# Windows toolkit regression tests

From a Linux host with GCC, liblzma development headers, MinGW-w64, Python 3,
and Wine installed, run:

```sh
make -C targets/toolkit_windows test
```

On a headless host, run the same command under `xvfb-run -a`. The test builds
the Windows tools, uses a temporary Wine prefix, and runs the actual `build.bat`
against every ABL checked into `ablrepo`. It compares the extracted and patched
files byte-for-byte with native Linux outputs. It also checks the missing-GBL
warning, paths with spaces and shell metacharacters, inherited delayed expansion,
missing inputs/tools, unsupported PE images, and stale outputs after failure.
It does not flash a device or require rebuilding BDS/UEFI applications.
The assertions check English guidance. Wine 10 may decode UTF-8 batch text
using its OEM code page despite `chcp 65001`, so these tests do not validate
Chinese console rendering.

To test an already unpacked release instead:

```sh
python3 targets/toolkit_windows/tests/test_wine.py --toolkit /path/to/toolkit
```

Wine requires permission to create local sockets and start its server. A Wine
startup failure is a test failure, not a skipped or successful test. In a
restricted environment, the native fixtures can be checked separately:

```sh
python3 targets/toolkit_windows/tests/test_wine.py --native-only
```

That command does **not** validate Windows executables or batch parsing.
