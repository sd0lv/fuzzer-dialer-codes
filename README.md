# Dialer Code Fuzzer & Bruteforcer

Fuzz Android **dialer (MMI / secret) codes** to discover hidden service menus.

Many Android devices expose engineering and diagnostic screens (EngineerMode,
hardware test / CIT, Testing settings, …) behind hidden *secret codes* such as
`*#*#4636#*#*`. This tool helps you discover them over `adb` on a
USB‑connected device.

## Requirements

- Python 3
- Android Platform Tools (`adb`) in your `PATH`
- A device with **USB debugging** enabled 

## Usage

```
usage: fuzzer_dialer.py [-h] [-l] [-i INPUTFILE] [-o OUTPUTFILE] [-bf] [-r]
                        [-s SERIAL] [--vendor {samsung,generic,all}]
                        [--dialer-package PKG] [--min-digits N]
                        [--max-digits N] [--limit N] [--delay S]
```

| Option | Description |
| --- | --- |
| `-l, --list-secrets` | Statically list secret codes registered on the device (dials nothing, works on any vendor) |
| `-i, --inputfile` | Dialer code wordlist (dictionary mode) |
| `-o, --outputfile` | File to append results to (required for dial modes; optional with `-l`) |
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

List registered secret codes:

```bash
python3 fuzzer_dialer.py -l
python3 fuzzer_dialer.py -l -o codes.txt          
python3 fuzzer_dialer.py -s emulator-5554 -l     
```

Dictionary mode against a wordlist 

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
