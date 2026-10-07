#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@sd0lv

DIALER CODE FUZZER AND BRUTEFORCER

Discover Android hidden "secret codes" (engineering / diagnostic menus) over adb
during an *authorized* mobile security assessment.

Two approaches:

  * List secret codes mode (-l / --list-secrets), RECOMMENDED: statically list
    every secret code registered on the device by parsing the PackageManager
    (android.provider.Telephony.SECRET_CODE receivers). Vendor-independent,
    fast, and dials NOTHING -- so it can never trigger a destructive code.

  * Dial modes (-i dictionary / -bf bruteforce), legacy: type each candidate
    code into the dialer and watch logcat for the framework acknowledging it.
    Detection is tuned for Samsung firmware, which logs:
        NumberLocationModel: ... getNumerLocation(<code>) : activated = true
        ParseService: uri : android_secret_code://<code>
    A --vendor generic profile matches the AOSP broadcast but is unverified on
    non-Samsung devices. Adjust the MATCH_* constants below for other vendors.
    
 usage: fuzzer_dialer.py [-h] [-i INPUTFILE] -o OUTPUTFILE [-bf]
 optional arguments:
   -h, --help            show this help message and exit
   -i INPUTFILE, --inputfile INPUTFILE
                         Dialer code list
   -o OUTPUTFILE, --outputfile OUTPUTFILE
                         File to save results
   -bf, --bruteforce     Bruteforce mode, inputfile not needed
   -r,  --random         Randomize "*#" digits in Bruteforce mode
   -l, --list-secrets    List secret codes registered on the device
   -s SERIAL             adb device serial

  Example:
  python3 fuzzer_dialer.py -i dialer.lst -o output.txt -bf  --> Dictionary Mode
  python3 fuzzer_dialer.py -o output.txt -bf  --> Bruteforce Mode
  python3 fuzzer_dialer.py -o output.txt -bf --random --> Bruteforce Mode, random *# digits
  python3 fuzzer_dialer.py -s emulator-5554 -l -> List secret codes on a device
  python3 fuzzer_dialer.py -l -o codes.txt -> List secret codes and save

"""

import argparse
import itertools
import random
import re
import signal
import subprocess
import sys
import time

# Logcat markers used to confirm a code was accepted
# Samsung firmware logs an explicit "activated = true" line followed by a
# ParseService line carrying the android_secret_code URI:
#     NumberLocationModel: ... getNumerLocation(*#1234#) : activated = true
#     ParseService: uri : android_secret_code://1234
MATCH_ACTIVATED = "activated = true"
MATCH_SECRET = "android_secret_code"
MATCH_SECRET_TAG = "ParseService"

# Generic AOSP marker: when a secret code is dialed, the phone app broadcasts
# android.provider.Telephony.SECRET_CODE with data android_secret_code://<code>.
# This is vendor-independent, though not every OEM logs it at default verbosity.
# NOTE: the generic profile is derived from the AOSP mechanism and has NOT been
# empirically validated on non-Samsung firmware. Verify on a disposable test
# device before relying on it.
VENDOR_PROFILES = ("samsung", "generic", "all")

# Package killed to keep the dialer UI from stacking up between attempts.
# Override with --dialer-package for non-Samsung devices, e.g.
# com.google.android.dialer (Pixel/Xiaomi) or com.android.dialer (AOSP).
DEFAULT_DIALER_PACKAGE = "com.samsung.android.dialer"

# Shown when a device refuses ADB input injection (typical on MIUI / HyperOS).
MIUI_ENABLE_HELP = """\
    On MIUI / HyperOS (Xiaomi / Redmi / POCO), ADB input injection is blocked by
    default, so the dial modes cannot type the codes. To enable it you must turn
    on the special "USB debugging (Security settings)" option:

      1. Sign in to a Mi account on the phone AND insert a SIM card
         (Xiaomi requires both before this option can be toggled).
      2. Enable Developer Options: Settings > About phone >
         tap "OS version" (or "MIUI version") 7 times.
      3. Settings > Additional settings > Developer options:
           - turn on "USB debugging"
           - turn on "USB debugging (Security settings)"   <-- the important one
             (this grants ADB permission to simulate input / manage the device).
      4. Replug the USB cable and accept the debugging prompt again.

    If you cannot enable it, use the list-secrets mode instead — it needs no
    input injection and works on any vendor:  fuzzer_dialer.py -l"""


class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


# ----------------------------------------------------------------------------
# adb helpers
# ----------------------------------------------------------------------------
def adb(serial, args, capture=False):
    """Run an adb command for the selected device.

    args is a list of tokens (no shell involved -> no injection surface).
    """
    cmd = ["adb", "-s", serial] + args
    if capture:
        return subprocess.run(
            cmd, capture_output=True, text=True
        ).stdout.strip()
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return None


def list_devices():
    """Return the serials of devices currently in 'device' state."""
    out = subprocess.run(
        ["adb", "devices"], capture_output=True, text=True
    ).stdout
    serials = []
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].strip() == "device":
            serials.append(parts[0].strip())
    return serials


def pick_device(requested):
    devices = list_devices()
    if not devices:
        sys.exit(
            Colors.FAIL + "[!] No adb devices in 'device' state. "
            "Connect and authorize a device first." + Colors.ENDC
        )
    if requested:
        if requested not in devices:
            sys.exit(
                Colors.FAIL + "[!] Device '%s' not found. Available: %s"
                % (requested, ", ".join(devices)) + Colors.ENDC
            )
        return requested
    if len(devices) > 1:
        sys.exit(
            Colors.FAIL + "[!] Multiple devices connected: %s\n"
            "    Choose one with --serial <id>."
            % ", ".join(devices) + Colors.ENDC
        )
    return devices[0]


def dial_code(serial, code, dialer_package):
    """Type a dialer code into the phone app and dismiss the screen."""
    # 'input text' runs in the device shell; escape '#' so it is not treated
    # as a comment, and spaces so tokens are not split.
    escaped = code.replace("#", "\\#").replace(" ", "\\ ")
    adb(serial, ["shell", "am", "start", "-a", "android.intent.action.DIAL"])
    adb(serial, ["shell", "input", "text", escaped])
    adb(serial, ["shell", "pkill", "-f", dialer_package])
    adb(serial, ["shell", "input", "keyevent", "4"])   # BACK
    adb(serial, ["shell", "input", "keyevent", "3"])   # HOME


def clean_device_screen(serial, dialer_package):
    adb(serial, ["shell", "input", "keyevent", "4"])
    adb(serial, ["shell", "input", "keyevent", "3"])
    adb(serial, ["shell", "pkill", "-f", dialer_package])


def input_injection_blocked(serial):
    """Return an error string if adb input injection is refused, else None.

    On MIUI/HyperOS, `input`/`keyevent` raise a SecurityException (INJECT_EVENTS)
    unless "USB debugging (Security settings)" is enabled, so dial modes can
    never type the codes. KEYCODE 0 (UNKNOWN) is a harmless no-op probe.
    """
    res = subprocess.run(
        ["adb", "-s", serial, "shell", "input", "keyevent", "0"],
        capture_output=True, text=True,
    )
    err = ((res.stderr or "") + (res.stdout or "")).strip()
    if "SecurityException" in err or "INJECT_EVENTS" in err:
        return err.splitlines()[0] if err else "input injection refused"
    return None


def read_recent_logcat(serial, since):
    """Return logcat lines emitted since the given device timestamp."""
    return adb(serial, ["logcat", "-d", "-t", since], capture=True) or ""


def device_timestamp(serial):
    """Current device time in the 'MM-DD HH:MM:SS.000' logcat format."""
    ts = adb(serial, ["shell", "date", "+%m-%d %H:%M:%S.000"], capture=True)
    return ts


_COMP_RE = re.compile(r"([\w.]+/[\w.$]+)")
_AUTH_RE = re.compile(r'Authority: "([^"]+)"')

# Component names that hint a code is destructive -> flagged, never triggered.
DANGER_RE = re.compile(r"reset|wipe|erase|factory|format", re.IGNORECASE)


def _packages_with_secret_codes(serial):
    """Package names that register an android_secret_code receiver."""
    dump = adb(serial, ["shell", "dumpsys", "package", "r"], capture=True) or ""
    pkgs, in_block = set(), False
    for line in dump.splitlines():
        if "android_secret_code:" in line:
            in_block = True
            continue
        if in_block:
            # Scheme blocks end at the next 'word:' header at the same indent.
            if re.match(r"\s+[\w.]+:\s*$", line) and "/" not in line:
                in_block = False
                continue
            m = _COMP_RE.search(line)
            if m:
                pkgs.add(m.group(1).split("/")[0])
    return sorted(pkgs)


def discover_secret_codes(serial):
    """Map each secret code on the device to the receivers that handle it.

    Returns {code: sorted([component, ...])}.
    """
    codes = {}
    for pkg in _packages_with_secret_codes(serial):
        dump = adb(serial, ["shell", "dumpsys", "package", pkg], capture=True) or ""
        comp, is_secret = None, False
        for line in dump.splitlines():
            m = re.search(r"([\w.]+/[\w.$]+) filter [0-9a-f]+", line)
            if m:
                comp, is_secret = m.group(1), False
                continue
            if 'Scheme: "android_secret_code"' in line:
                is_secret = True
                continue
            a = _AUTH_RE.search(line)
            if a and is_secret and comp:
                codes.setdefault(a.group(1), set()).add(comp)
    return {c: sorted(v) for c, v in codes.items()}


def render_secret_codes(codes, out):
    """Print (and optionally save) the listed secret code table."""
    header = "\n" + "*" * 76 + "\n" + \
        (" SECRET CODES REGISTERED ON DEVICE (%d) " % len(codes)).center(76, "*") + \
        "\n" + "*" * 76
    print(Colors.BOLD + Colors.HEADER + header + Colors.ENDC)
    out.write(header + "\n")
    if not codes:
        msg = "(no android_secret_code receivers found)"
        print(msg)
        out.write(msg + "\n")
        return
    for code in sorted(codes, key=lambda x: (len(x), x)):
        comps = ", ".join(codes[code])
        danger = bool(DANGER_RE.search(comps))
        dial = "*#*#%s#*#*" % code
        mark = "  [!] POTENTIALLY DESTRUCTIVE" if danger else ""
        color = Colors.FAIL if danger else Colors.OKGREEN
        print(color + Colors.BOLD + "%-16s" % dial + Colors.ENDC
              + " -> " + comps + (Colors.FAIL + mark + Colors.ENDC if danger else ""))
        out.write("%-16s -> %s%s\n" % (dial, comps, mark))
    out.flush()


# ----------------------------------------------------------------------------
# Matching / reporting
# ----------------------------------------------------------------------------
def _report_hit(code, line, out):
    print(line)
    print(Colors.OKGREEN + "CORRECT DIALER CODE: " + code + Colors.ENDC)
    out.write(line + "\n")
    out.write("CORRECT DIALER CODE: " + code + "\n")


def match_dialer_code(serial, code, since, out, vendor):
    """Check logcat for confirmation that `code` was accepted"""
    code = code.replace("\\", "")
    digits = re.sub(r"[*#]", "", code)  # e.g. '*#1234#' -> '1234'
    header = "\n" + "*" * 76
    print(header)
    print(Colors.BOLD + "Trying: " + code + Colors.ENDC)
    out.write(header + "\nTrying: " + code + "\n")

    log = read_recent_logcat(serial, since)
    want_samsung = vendor in ("samsung", "all")
    want_generic = vendor in ("generic", "all")

    activated = False
    found = None
    for line in log.splitlines():
        # Samsung: "activated = true" for this code, then a ParseService URI.
        if want_samsung:
            if MATCH_ACTIVATED in line and code in line:
                print(line)
                out.write(line + "\n")
                activated = True
            if MATCH_SECRET in line and MATCH_SECRET_TAG in line and activated:
                _report_hit(code, line, out)
                found = found or code
        # Generic AOSP: any secret_code broadcast line referencing the code.
        if want_generic and MATCH_SECRET in line and digits and digits in line:
            _report_hit(code, line, out)
            found = found or code
    out.flush()
    return found


def summary_table(out, found_codes):
    banner = (
        "\n\n" + "*" * 76 +
        "\n" + " SUMMARY ".center(76, "*") +
        "\n" + " DIALER CODES FOUND ".center(76, "*") +
        "\n" + "*" * 76 + "\n"
    )
    body = "\n".join(found_codes) if found_codes else "(none)"
    print(Colors.BOLD + Colors.HEADER + banner + Colors.ENDC)
    print(Colors.BOLD + Colors.OKGREEN + body + Colors.ENDC + "\n")
    out.write(banner)
    out.write(body + "\n")
    out.flush()


# ----------------------------------------------------------------------------
# Bruteforce candidate generation
# ----------------------------------------------------------------------------
def prefix_suffix_combos(max_len=4):
    """All combinations of '*' and '#' of length 0..max_len (as in v1.x)."""
    combos = [""]
    for length in range(1, max_len + 1):
        combos += ["".join(p) for p in itertools.product("*#", repeat=length)]
    return combos


def random_number(min_digits, max_digits):
    """A zero-padded random number whose length is in [min, max] digits."""
    n = random.randint(min_digits, max_digits)
    low, high = 10 ** (n - 1), (10 ** n) - 1
    return str(random.randint(low, high)).zfill(n)


def iter_bruteforce(randomize, min_digits, max_digits, limit):
    """Yield candidate codes for bruteforce mode.

    Numbers are unique for the run. With --random every '*'/'#' prefix/suffix
    combination wraps each number; otherwise the classic '*#<num>#' form is used.
    """
    combos = prefix_suffix_combos() if randomize else None
    seen = set()
    produced = 0
    # Cap the unique-number space so we don't spin forever on collisions.
    space = (10 ** max_digits) - (10 ** (min_digits - 1))
    while limit is None or produced < limit:
        if len(seen) >= space:
            return
        num = random_number(min_digits, max_digits)
        if num in seen:
            continue
        seen.add(num)
        if randomize:
            for pre in combos:
                for suf in combos:
                    yield pre + num + suf
                    produced += 1
                    if limit is not None and produced >= limit:
                        return
        else:
            yield "*#" + num + "#"
            produced += 1


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="DIALER CODE FUZZER AND BRUTEFORCER",
        epilog=(
            "Examples:\n"
            "  fuzzer_dialer.py -l                              # list secret codes (recommended)\n"
            "  fuzzer_dialer.py -l -o codes.txt                 # list secret codes + save\n"
            "  fuzzer_dialer.py -i dialer.lst -o out.txt        # dictionary (dials codes)\n"
            "  fuzzer_dialer.py -bf -o out.txt                  # bruteforce mode\n"
            "  fuzzer_dialer.py -bf -r -o out.txt               # bruteforce, random *# digits\n"
            "  fuzzer_dialer.py -s emulator-5554 -l"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-l", "--list-secrets", action="store_true",
                   help="Statically list the secret codes registered on the "
                        "device (vendor-independent, dials nothing). Recommended.")
    p.add_argument("-i", "--inputfile", help="Dialer code wordlist (dictionary mode)")
    p.add_argument("-o", "--outputfile",
                   help="File to save results (required unless -l/--list-secrets)")
    p.add_argument("-bf", "--bruteforce", action="store_true",
                   help="Bruteforce mode (no wordlist needed)")
    p.add_argument("-r", "--random", action="store_true",
                   help='Randomize "*#" prefix/suffix in bruteforce mode')
    p.add_argument("-s", "--serial", help="adb device serial (required if >1 device)")
    p.add_argument("--vendor", choices=VENDOR_PROFILES, default="all",
                   help="Detection profile: samsung, generic (AOSP), or all "
                        "(default). 'generic' is unverified on non-Samsung.")
    p.add_argument("--dialer-package", default=DEFAULT_DIALER_PACKAGE,
                   help="Dialer package to kill between attempts "
                        "(default %s; e.g. com.google.android.dialer)"
                        % DEFAULT_DIALER_PACKAGE)
    p.add_argument("--min-digits", type=int, default=1,
                   help="Min number length in bruteforce mode (default 1)")
    p.add_argument("--max-digits", type=int, default=6,
                   help="Max number length in bruteforce mode (default 6)")
    p.add_argument("--limit", type=int, default=None,
                   help="Max candidates to try in bruteforce mode (default: unbounded)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Seconds to wait between attempts (default 0)")
    return p


class _NullWriter:
    def write(self, *_): pass
    def flush(self): pass
    def close(self): pass


def main():
    args = build_parser().parse_args()

    if not args.list_secrets:
        if not args.outputfile:
            sys.exit(Colors.FAIL + "[!] -o/--outputfile is required (or use -l)." + Colors.ENDC)
        if not args.bruteforce and not args.inputfile:
            sys.exit(Colors.FAIL + "[!] Provide a wordlist with -i, or use -bf/-l." + Colors.ENDC)
    if args.min_digits < 1 or args.max_digits < args.min_digits:
        sys.exit(Colors.FAIL + "[!] Invalid --min-digits/--max-digits range." + Colors.ENDC)

    serial = pick_device(args.serial)
    print(Colors.OKBLUE + "[*] Target device: " + serial + Colors.ENDC)

    out = open(args.outputfile, "a") if args.outputfile else _NullWriter()

    # List-secrets mode: list registered secret codes, dial nothing, then exit.
    if args.list_secrets:
        print(Colors.BOLD + Colors.WARNING
              + "Listing registered secret codes (no codes are dialed)..."
              + Colors.ENDC)
        render_secret_codes(discover_secret_codes(serial), out)
        out.close()
        return

    # Dial modes must inject input to type codes; MIUI/HyperOS often blocks this
    # silently. Fail loudly with guidance instead of "dialing" nothing.
    blocked = input_injection_blocked(serial)
    if blocked:
        print(Colors.FAIL + Colors.BOLD
              + "[!] ADB input injection is blocked on this device:" + Colors.ENDC)
        print(Colors.FAIL + "    " + blocked + Colors.ENDC)
        print(Colors.WARNING + "    Codes cannot be typed, so the dial modes "
              "(-i / -bf) will not work here.\n" + Colors.ENDC)
        print(Colors.WARNING + MIUI_ENABLE_HELP + Colors.ENDC)
        out.close()
        sys.exit(2)

    found_codes = []
    done = {"flag": False}

    def try_code(code):
        code = code.strip()
        if not code:
            return
        since = device_timestamp(serial)
        dial_code(serial, code, args.dialer_package)
        if args.delay:
            time.sleep(args.delay)
        hit = match_dialer_code(serial, code, since, out, args.vendor)
        if hit:
            found_codes.append(hit)

    def finish():
        if done["flag"]:
            return
        done["flag"] = True
        summary_table(out, found_codes)
        out.close()

    def on_sigint(*_):
        finish()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    try:
        clean_device_screen(serial, args.dialer_package)
        if args.bruteforce:
            mode = "Random [*#] values" if args.random else "Static [*#] values"
            print(Colors.BOLD + Colors.WARNING + "Bruteforce mode selected! "
                  + mode + Colors.ENDC + "\n")
            for code in iter_bruteforce(args.random, args.min_digits,
                                        args.max_digits, args.limit):
                try_code(code)
        else:
            print(Colors.BOLD + Colors.WARNING
                  + "Dictionary attack mode selected!" + Colors.ENDC + "\n")
            with open(args.inputfile) as f:
                for line in f:
                    try_code(line)
    finally:
        finish()


if __name__ == "__main__":
    main()
