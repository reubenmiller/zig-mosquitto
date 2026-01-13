const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const with_tls = b.option(bool, "WITH_TLS", "Build mosquitto with TLS") orelse false;
    const version = b.option([]const u8, "version", "mosquitto version string") orelse "2.0.99";

    const exe = b.addExecutable(.{
        .name = "mosquitto",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.addIncludePath(b.path("mosquitto"));
    exe.addIncludePath(b.path("mosquitto/src"));
    exe.addIncludePath(b.path("mosquitto/common"));
    exe.addIncludePath(b.path("mosquitto/lib"));
    exe.addIncludePath(b.path("mosquitto/libcommon"));
    exe.addIncludePath(b.path("mosquitto/deps"));
    exe.addIncludePath(b.path("mosquitto/include"));

    const cjson_dep = b.dependency("cjson", .{});
    const mkdir_cjson = b.addSystemCommand(&[_][]const u8{"mkdir", "-p", "cjson"});
    const copy_cjson = b.addSystemCommand(&[_][]const u8{"cp"});
    copy_cjson.addFileArg(cjson_dep.path("cJSON.h"));
    copy_cjson.addArg("cjson/cJSON.h");
    copy_cjson.step.dependOn(&mkdir_cjson.step);
    exe.step.dependOn(&copy_cjson.step);
    exe.addIncludePath(b.path("."));
    exe.addCSourceFile(.{ .file = cjson_dep.path("cJSON.c"), .flags = &.{} });

    const sqlite_dep = b.dependency("sqlite", .{});
    exe.addIncludePath(sqlite_dep.path("."));
    exe.addCSourceFile(.{ .file = sqlite_dep.path("sqlite3.c"), .flags = &.{} });

    // Enable openssl
    if (with_tls) {
        const openssl = b.dependency("openssl", .{ .target = target, .optimize = optimize });
        const libssl = openssl.artifact("ssl");
        const libcrypto = openssl.artifact("crypto");
        _ = for (libcrypto.root_module.include_dirs.items) |include_dir| {
            try exe.root_module.include_dirs.append(b.allocator, include_dir);
        };
        // _ = for (libssl.root_module.include_dirs.items) |include_dir| {
        //     try exe.root_module.include_dirs.append(b.allocator, include_dir);
        // };
        exe.root_module.linkLibrary(libssl);
        exe.root_module.linkLibrary(libcrypto);
    }

    const mosquitto_sources = [_][]const u8{
        "mosquitto/common/json_help.c",

        "mosquitto/libcommon/base64_common.c",
        "mosquitto/libcommon/cjson_common.c",
        "mosquitto/libcommon/file_common.c",
        "mosquitto/libcommon/memory_common.c",
        "mosquitto/libcommon/mqtt_common.c",
        "mosquitto/libcommon/password_common.c",
        "mosquitto/libcommon/property_common.c",
        "mosquitto/libcommon/random_common.c",
        "mosquitto/libcommon/strings_common.c",
        "mosquitto/libcommon/time_common.c",
        "mosquitto/libcommon/topic_common.c",
        "mosquitto/libcommon/utf8_common.c",

        "mosquitto/lib/alias_mosq.c",
        "mosquitto/lib/handle_ping.c",
        "mosquitto/lib/handle_pubackcomp.c",
        "mosquitto/lib/handle_pubrec.c",
        "mosquitto/lib/handle_pubrel.c",
        "mosquitto/lib/handle_suback.c",
        "mosquitto/lib/handle_unsuback.c",
        "mosquitto/lib/net_mosq_ocsp.c",
        "mosquitto/lib/net_mosq.c",
        "mosquitto/lib/net_ws.c",
        "mosquitto/lib/packet_datatypes.c",
        "mosquitto/lib/packet_mosq.c",
        "mosquitto/lib/property_mosq.c",
        "mosquitto/lib/send_mosq.c",
        "mosquitto/lib/send_connect.c",
        "mosquitto/lib/send_disconnect.c",
        "mosquitto/lib/send_publish.c",
        "mosquitto/lib/send_subscribe.c",
        "mosquitto/lib/send_unsubscribe.c",
        "mosquitto/lib/tls_mosq.c",
        "mosquitto/lib/util_mosq.c",
        "mosquitto/lib/will_mosq.c",

        "mosquitto/plugins/acl-file/acl_check.c",
        "mosquitto/plugins/acl-file/acl_parse.c",
        "mosquitto/plugins/password-file/password_check.c",
        "mosquitto/plugins/password-file/password_parse.c",

        "mosquitto/src/acl_file.c",
        "mosquitto/src/bridge.c",
        "mosquitto/src/bridge_topic.c",
        "mosquitto/src/broker_control.c",
        "mosquitto/src/conf.c",
        "mosquitto/src/conf_includedir.c",
        "mosquitto/src/context.c",
        "mosquitto/src/control.c",
        "mosquitto/src/control_common.c",
        "mosquitto/src/database.c",
        "mosquitto/src/handle_auth.c",
        "mosquitto/src/handle_connack.c",
        "mosquitto/src/handle_connect.c",
        "mosquitto/src/handle_disconnect.c",
        "mosquitto/src/handle_publish.c",
        "mosquitto/src/handle_subscribe.c",
        "mosquitto/src/handle_unsubscribe.c",
        // "mosquitto/src/http_api.c",
        // "mosquitto/src/http_serv.c",
        "mosquitto/src/keepalive.c",
        "mosquitto/src/listeners.c",
        "mosquitto/src/logging.c",
        "mosquitto/src/loop.c",
        "mosquitto/src/mosquitto.c",
        "mosquitto/src/mux.c",
        "mosquitto/src/mux_epoll.c",
        "mosquitto/src/mux_kqueue.c",
        "mosquitto/src/mux_poll.c",
        "mosquitto/src/net.c",
        "mosquitto/src/password_file.c",
        "mosquitto/src/persist_read.c",
        "mosquitto/src/persist_read_v234.c",
        "mosquitto/src/persist_read_v5.c",
        "mosquitto/src/persist_write.c",
        "mosquitto/src/persist_write_v5.c",
        "mosquitto/src/plugin_acl_check.c",
        "mosquitto/src/plugin_basic_auth.c",
        "mosquitto/src/plugin_callbacks.c",
        "mosquitto/src/plugin_cleanup.c",
        "mosquitto/src/plugin_client_offline.c",
        "mosquitto/src/plugin_connect.c",
        "mosquitto/src/plugin_disconnect.c",
        "mosquitto/src/plugin_extended_auth.c",
        "mosquitto/src/plugin_init.c",
        "mosquitto/src/plugin_message.c",
        "mosquitto/src/plugin_persist.c",
        "mosquitto/src/plugin_psk_key.c",
        "mosquitto/src/plugin_public.c",
        "mosquitto/src/plugin_reload.c",
        "mosquitto/src/plugin_subscribe.c",
        "mosquitto/src/plugin_tick.c",
        "mosquitto/src/plugin_unsubscribe.c",
        "mosquitto/src/plugin_v2.c",
        "mosquitto/src/plugin_v3.c",
        "mosquitto/src/plugin_v4.c",
        "mosquitto/src/plugin_v5.c",
        "mosquitto/src/property_broker.c",
        "mosquitto/src/proxy_v1.c",
        "mosquitto/src/proxy_v2.c",
        "mosquitto/src/psk_file.c",
        "mosquitto/src/read_handle.c",
        "mosquitto/src/retain.c",
        "mosquitto/src/security_default.c",
        "mosquitto/src/send_auth.c",
        "mosquitto/src/send_connack.c",
        "mosquitto/src/send_suback.c",
        "mosquitto/src/send_unsuback.c",
        "mosquitto/src/service.c",
        "mosquitto/src/session_expiry.c",
        "mosquitto/src/signals.c",
        "mosquitto/src/subs.c",
        "mosquitto/src/sys_tree.c",
        "mosquitto/src/topic_tok.c",
        "mosquitto/src/watchdog.c",
        "mosquitto/src/websockets.c",
        "mosquitto/src/will_delay.c",
        "mosquitto/src/xtreport.c",
    };

    // construct build arguments
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    const alloc = gpa.allocator();
    var mosquitto_broker_flags = std.array_list.Managed([]const u8).init(alloc);
    defer mosquitto_broker_flags.deinit();

    // optional flags
    try mosquitto_broker_flags.append("-DWITH_BROKER");
    if (with_tls) {
        try mosquitto_broker_flags.append("-DWITH_TLS");
    }

    // common flags
    try mosquitto_broker_flags.append("-DWITH_BRIDGE");
    try mosquitto_broker_flags.append("-DWITH_PERSISTENCE");
    try mosquitto_broker_flags.append("-DWITH_SQLITE");

    // version
    const version_flag = try std.fmt.allocPrint(alloc, "-DVERSION=\"{s}\"", .{version});
    defer alloc.free(version_flag);
    try mosquitto_broker_flags.append(version_flag);

    try mosquitto_broker_flags.append("-Wall");
    try mosquitto_broker_flags.append("-W");

    exe.addCSourceFiles(.{
        .files = &mosquitto_sources,
        .flags = mosquitto_broker_flags.items,
    });
    exe.linkLibC();

    b.installArtifact(exe);
}
