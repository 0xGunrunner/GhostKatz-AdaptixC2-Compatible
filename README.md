# GhostKatz-AdaptixC2

Fork of [RainbowDynamix/GhostKatz](https://github.com/RainbowDynamix/GhostKatz) adapted for [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2), supporting both **Beacon** and **Kharon** agents.

Original BOF, technique, and driver abuse research belong to [@RainbowDynamix](https://github.com/RainbowDynamix). This fork only ports the operator-facing integration from Cobalt Strike's `.cna` to AdaptixC2's `.axs` format, and adds a small source patch for Kharon compatibility.

## What this fork changes

- Replaces `ghostkatz.cna` with `ghostkatz.axs` (AdaptixC2 extension script)
- Auto-detects agent type and uses the correct cleanup command (`rm` on Beacon, `fs rm` on Kharon)
- Adds a small, non-fatal patch to `main.c` so the BOF runs correctly under Kharon's BOF loader

## Usage

```
ghostkatz logonpasswords -prv 1
ghostkatz wdigest -prv 2
```

Arguments:
- `mode` — `logonpasswords` (NT + SHA1 hashes from MSV1_0) or `wdigest` (plaintext, only populated when `UseLogonCredential = 1`)
- `-prv <n>` — provider: `1` = `tpwsav.sys`, `2` = `throttlestop.sys`

The extension handles driver staging, BOF execution, and cleanup as three chained tasks. Allow a few seconds between consecutive runs to let the previous cleanup task complete — firing runs back-to-back can race the next upload against the previous `fs rm`, causing `Failed to start service : 2` (ERROR_FILE_NOT_FOUND).

SYSTEM context is required. BYOVD provider drivers must not be AV-quarantined before staging — test in your lab environment first.

## Installation

1. Clone this repo into your AdaptixC2 extensions directory
2. Load `ghostkatz.axs` through the AdaptixC2 operator UI (Extender Manager)
3. Confirm the `ghostkatz` command appears in `help`

Place the compiled BOF (`ghostkatz.x64.o`) in `_bin/` and the drivers in `drivers/` relative to the `.axs` file. See the Makefile inherited from upstream for rebuilding the BOF from source.

## The Kharon patch

GhostKatz's BOF fails on Kharon at this check in `main.c`:

```c
if (BeaconDataLength(&parser) != 0) {
    BeaconPrintf(CALLBACK_ERROR, "Invalid number of arguments!");
    return FALSE;
}
```

After extracting the expected arguments (`-prv` flag string, provider int, mode string), Kharon's BOF loader leaves residual bytes in the argument buffer — 25 to 32 bytes depending on argument length. Beacon's BOF loader leaves zero. The original check treats any residual bytes as a fatal error.

This fork changes it to non-fatal:

```c
if (BeaconDataLength(&parser) != 0) {
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Note: %d trailing bytes in arg buffer (non-fatal)",
                 BeaconDataLength(&parser));
}
```

With that change, GhostKatz produces identical credential output under Kharon as under Beacon.

I haven't traced the root cause of the byte difference down to a specific line in AdaptixC2's extender source. The residual size scales roughly with the length of the string arguments, suggesting the Kharon `cstr` packer in `AdaptixC2/AdaptixServer/extenders/agent_kharon/` handles something around the null terminator or length-prefix differently from the Beacon packer. PRs welcome from anyone willing to dig into the AdaptixC2 Go code.

## Operator notes for Kharon

A few differences from Beacon worth knowing if you're porting other BOFs:

- `rm` is a subcommand under `fs` on Kharon (`fs rm <path>`), not a top-level command
- `upload <local> <remote>` works as documented, but chaining upload → BOF → cleanup within a single `execute_alias`-based preHook can race if runs are fired back-to-back faster than the previous cleanup completes
- Kharon's BOF loader leaves trailing bytes in the arg buffer after extraction; any BOF that does strict `BeaconDataLength(&parser) != 0` checks will fail under Kharon without a patch

## Credits

- [@RainbowDynamix](https://github.com/RainbowDynamix) — original GhostKatz BOF, driver abuse research, and technique
- [oblivion](https://github.com/entropy-z) — for pointing me at DebugView/WinDbg + Kharon's `DbgPrint` output when I was stuck debugging

## Disclaimer

I'm an offensive security practitioner, not a malware developer. The fix in this fork is pragmatic — it works, but I don't claim deep understanding of AdaptixC2's extender internals. If someone with that expertise wants to submit a proper upstream fix that eliminates the trailing-byte difference at the packer level, I'd welcome it.

Use only against systems you are authorized to test. The vulnerable drivers bundled here (`tpwsav.sys`, `throttlestop.sys`) are on EDR vendor block lists and will be detected in most modern environments without prior EDR evasion steps.

## License

Same as upstream GhostKatz.
