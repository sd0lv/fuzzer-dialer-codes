# Dialer Code Fuzzer & Bruteforcer

Fuzz Android **dialer (MMI / secret) codes** to discover hidden service menus
during an *authorized* mobile security assessment.

Many Android devices expose engineering and diagnostic screens (EngineerMode,
hardware test / CIT, Testing settings, …) behind hidden *secret codes* such as
`*#*#4636#*#*`. This tool helps you discover them over `adb` on a
USB‑connected device.

It offers two approaches:

### 1. Enumeration mode (`-e`) — recommended, universal, non‑destructive

Secret codes are declared by installed apps as broadcast receivers with an
intent‑filter for `android.provider.Telephony.SECRET_CODE` and a data URI
`android_secret_code://<code>`. `dumpsys` exposes `<code>` as the filter
*Authority*, so the tool can list **every real secret code on the device without
dialing anything**:

```bash
python3 fuzzer_dialer.py -e
```

This is **vendor‑independent** (Samsung, Xiaomi/HyperOS, Pixel, …), fast, and —
crucially — **safe**: because nothing is dialed, you cannot accidentally trigger
a destructive code. Codes whose receiver looks destructive (e.g. a factory‑reset
receiver) are flagged `[!] POTENTIALLY DESTRUCTIVE` in the output.

### 2. Dial modes (`-i` dictionary / `-bf` bruteforce) — legacy

The original approach: type each candidate code into the dialer and watch
`logcat` for the framework acknowledging it. Detection is tuned for **Samsung**
firmware, which logs:

```
NumberLocationModel: [D] [SEC] getNumerLocation(*#1234#) : activated = true
ParseService: uri : android_secret_code://1234
```

A `generic` AOSP profile also matches the `android_secret_code://` broadcast, but
this is **not reliable on all vendors** (e.g. on a Xiaomi Redmi Note 12 Pro the
broadcast is not surfaced in `logcat`). Prefer enumeration mode unless you
specifically need to *trigger* a code. Adjust the `MATCH_*` constants near the
top of `fuzzer_dialer.py` for other vendors.

> ⚠️ **Authorized use only.** Run this only against devices you own or are
> explicitly authorized to test — a wordlist/bruteforce run *dials* codes and
> some (factory reset, EEP reset, …) are destructive. Enumeration mode (`-e`)
> dials nothing and is always safe to run. You are responsible for how you use
> this tool.

## Requirements

- Python 3 (tested on 3.13)
- Android Platform Tools (`adb`) in your `PATH`
- A device with **USB debugging** enabled and authorized (`adb devices` shows it
  as `device`)

No third‑party Python packages are needed (standard library only).

## Usage

```
usage: fuzzer_dialer.py [-h] [-e] [-i INPUTFILE] [-o OUTPUTFILE] [-bf] [-r]
                        [-s SERIAL] [--vendor {samsung,generic,all}]
                        [--dialer-package PKG] [--min-digits N]
                        [--max-digits N] [--limit N] [--delay S]
```

| Option | Description |
| --- | --- |
| `-e, --enumerate` | **Recommended.** Statically list secret codes registered on the device (dials nothing, works on any vendor) |
| `-i, --inputfile` | Dialer code wordlist (dictionary mode) |
| `-o, --outputfile` | File to append results to (required for dial modes; optional with `-e`) |
| `-bf, --bruteforce` | Bruteforce mode (no wordlist needed) |
| `-r, --random` | Randomize `*` / `#` prefix & suffix in bruteforce mode |
| `-s, --serial` | adb device serial (required if more than one device is connected) |
| `--vendor` | Detection profile: `samsung`, `generic` (AOSP broadcast), or `all` (default) |
| `--dialer-package` | Dialer package to kill between attempts (default Samsung; e.g. `com.google.android.dialer`) |
| `--min-digits` | Min number length in bruteforce mode (default `1`) |
| `--max-digits` | Max number length in bruteforce mode (default `6`) |
| `--limit` | Max candidates to try in bruteforce mode (default: unbounded) |
| `--delay` | Seconds to wait between attempts (default `0`) |

### Examples

Enumerate registered secret codes (recommended, dials nothing):

```bash
python3 fuzzer_dialer.py -e
python3 fuzzer_dialer.py -e -o codes.txt          # also save to a file
python3 fuzzer_dialer.py -s emulator-5554 -e      # pick a specific device
```

Example output (Xiaomi Redmi Note 12 Pro, 86 codes found — excerpt):

```
*#*#4636#*#*     -> com.android.settings/.TestingSettingsBroadcastReceiver
*#*#6484#*#*     -> com.miui.cit/.receiver.CitBroadcastReceiver
*#*#3646633#*#*  -> com.mediatek.engineermode/.EngineerModeReceiver
*#*#1217#*#*     -> com.android.settings/.MiuiFactoryResetBroadcastReceiver  [!] POTENTIALLY DESTRUCTIVE
```

Dictionary mode against a bundled wordlist (dials each code — Samsung):

```bash
python3 fuzzer_dialer.py -i dialer.lst -o out.txt
```

Bruteforce mode (classic `*#<number>#` form):

```bash
python3 fuzzer_dialer.py -bf --limit 500 -o out.txt
```

Bruteforce with randomized `*#` prefixes/suffixes, picking a specific device:

```bash
python3 fuzzer_dialer.py -bf -r -s emulator-5554 --limit 500 -o out.txt
```

Press **Ctrl+C** at any time to stop early and print/save the summary of codes
found so far.

## Wordlists

- `dialer.lst` — general dialer/secret code list
- `dialer_custom.lst` — smaller curated set
- `dialer_old.lst` — legacy list kept for reference

## Vendor support

- **Enumeration mode (`-e`)** is fully **vendor‑independent** — it reads the
  PackageManager, not vendor log strings — and is validated on Samsung and on
  Xiaomi (HyperOS). Use it by default.
- **Dial modes (`-i` / `-bf`)** detection is **validated on Samsung** only. A
  `generic` profile matches the AOSP `android_secret_code://<code>` broadcast,
  but this is **not** reliable on non‑Samsung devices — e.g. on a Xiaomi Redmi
  Note 12 Pro (HyperOS + Google Dialer) typing the code works but the broadcast
  is not surfaced in `logcat`. On non‑Samsung devices also set
  `--dialer-package` (e.g. `com.google.android.dialer`).

Contributions confirming the correct log markers for other vendors are welcome.

## Notes & limitations

- Detection strings are **Samsung‑specific** by default (see `MATCH_*` constants).
- Bruteforce generates random, non‑repeating numbers per run; it does **not**
  guarantee exhaustive coverage — use `--limit`, `--min-digits` and
  `--max-digits` to scope the run.
- Typing codes into the dialer is inherently slow (one UI round‑trip + a logcat
  read per attempt). Prefer a good wordlist over blind bruteforce.

## Legacy

The original Python 2 versions are preserved under [`python2/`](python2/) for
reference. The Python 3 rewrite at the repo root is the supported version.

## License

[MIT](LICENSE) © sd0lv
