const std = @import("std");
const zon = @import("build.zig.zon");

pub fn build(b: *std.Build) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    const alloc = gpa.allocator();

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const with_tls = b.option(bool, "WITH_TLS", "Build mosquitto with TLS") orelse true;
    const version = b.option([]const u8, "version", "mosquitto version string") orelse zon.version;
    const with_dynamic_security = b.option(bool, "WITH_DYNAMIC_SECURITY", "Build dynamic-security plugin .so") orelse true;
    const with_persist_sqlite = b.option(bool, "WITH_PERSIST_SQLITE", "Build persist-sqlite plugin .so") orelse true;
    const with_acl_file_plugin = b.option(bool, "WITH_ACL_FILE_PLUGIN", "Build acl-file plugin .so") orelse true;
    const with_password_file_plugin = b.option(bool, "WITH_PASSWORD_FILE_PLUGIN", "Build password-file plugin .so") orelse true;
    const with_sparkplug_aware = b.option(bool, "WITH_SPARKPLUG_AWARE", "Build sparkplug-aware plugin .so") orelse true;

    const mosquitto = b.addExecutable(.{
        .name = "mosquitto",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    const mosquitto_dep = b.dependency("mosquitto_src", .{});

    mosquitto.root_module.addIncludePath(mosquitto_dep.path(""));
    mosquitto.root_module.addIncludePath(mosquitto_dep.path("src"));
    mosquitto.root_module.addIncludePath(mosquitto_dep.path("common"));
    mosquitto.root_module.addIncludePath(mosquitto_dep.path("lib"));
    mosquitto.root_module.addIncludePath(mosquitto_dep.path("libcommon"));
    mosquitto.root_module.addIncludePath(mosquitto_dep.path("deps"));
    mosquitto.root_module.addIncludePath(mosquitto_dep.path("include"));

    const cjson_dep = b.dependency("cjson", .{});
    const mkdir_cjson = b.addSystemCommand(&[_][]const u8{ "mkdir", "-p", "cjson" });
    const copy_cjson = b.addSystemCommand(&[_][]const u8{"cp"});
    copy_cjson.addFileArg(cjson_dep.path("cJSON.h"));
    copy_cjson.addArg("cjson/cJSON.h");
    copy_cjson.step.dependOn(&mkdir_cjson.step);
    mosquitto.step.dependOn(&copy_cjson.step);
    mosquitto.root_module.addIncludePath(b.path("."));
    mosquitto.root_module.addCSourceFile(.{ .file = cjson_dep.path("cJSON.c"), .flags = &.{} });

    const sqlite_dep = b.dependency("sqlite", .{});
    mosquitto.root_module.addIncludePath(sqlite_dep.path("."));
    mosquitto.root_module.addCSourceFile(.{ .file = sqlite_dep.path("sqlite3.c"), .flags = &.{} });

    const microhttpd = b.dependency("microhttpd", .{});
    mosquitto.root_module.addIncludePath(microhttpd.path("src/include"));

    // Enable openssl (artifacts stored in outer vars for reuse in plugin builds)
    var opt_libssl: ?*std.Build.Step.Compile = null;
    var opt_libcrypto: ?*std.Build.Step.Compile = null;
    if (with_tls) {
        const openssl = b.dependency("openssl", .{ .target = target, .optimize = optimize });
        opt_libssl = openssl.artifact("ssl");
        opt_libcrypto = openssl.artifact("crypto");
        mosquitto.root_module.linkLibrary(opt_libssl.?);
        mosquitto.root_module.linkLibrary(opt_libcrypto.?);
        mosquitto.root_module.addIncludePath(opt_libssl.?.getEmittedIncludeTree());
        mosquitto.root_module.addIncludePath(opt_libcrypto.?.getEmittedIncludeTree());
    }

    // note: Ideally the source code files should be sorted and the unused files should
    // be commented out rather than deleted from the list to make it easier to see what
    // is and isn't used
    const mosquitto_sources = [_][]const u8{
        "common/json_help.c",

        "libcommon/base64_common.c",
        "libcommon/cjson_common.c",
        "libcommon/file_common.c",
        "libcommon/memory_common.c",
        "libcommon/mqtt_common.c",
        "libcommon/password_common.c",
        "libcommon/property_common.c",
        "libcommon/random_common.c",
        "libcommon/strings_common.c",
        "libcommon/time_common.c",
        "libcommon/topic_common.c",
        "libcommon/utf8_common.c",

        "lib/alias_mosq.c",
        "lib/handle_ping.c",
        "lib/handle_pubackcomp.c",
        "lib/handle_pubrec.c",
        "lib/handle_pubrel.c",
        "lib/handle_suback.c",
        "lib/handle_unsuback.c",
        "lib/net_mosq_ocsp.c",
        "lib/net_mosq.c",
        "lib/net_ws.c",
        "lib/packet_datatypes.c",
        "lib/packet_mosq.c",
        "lib/property_mosq.c",
        "lib/send_mosq.c",
        "lib/send_connect.c",
        "lib/send_disconnect.c",
        "lib/send_publish.c",
        "lib/send_subscribe.c",
        "lib/send_unsubscribe.c",
        "lib/tls_mosq.c",
        "lib/util_mosq.c",
        "lib/will_mosq.c",

        "plugins/acl-file/acl_check.c",
        "plugins/acl-file/acl_parse.c",
        "plugins/password-file/password_check.c",
        "plugins/password-file/password_parse.c",

        "src/acl_file.c",
        "src/bridge.c",
        "src/bridge_topic.c",
        "src/broker_control.c",
        "src/conf.c",
        "src/conf_includedir.c",
        "src/context.c",
        "src/control.c",
        "src/control_common.c",
        "src/database.c",
        "src/handle_auth.c",
        "src/handle_connack.c",
        "src/handle_connect.c",
        "src/handle_disconnect.c",
        "src/handle_publish.c",
        "src/handle_subscribe.c",
        "src/handle_unsubscribe.c",
        "src/http_api.c",
        "src/http_serv.c",
        "src/keepalive.c",
        "src/listeners.c",
        "src/logging.c",
        "src/loop.c",
        "src/mosquitto.c",
        "src/mux.c",
        "src/mux_epoll.c",
        "src/mux_kqueue.c",
        "src/mux_poll.c",
        "src/net.c",
        "src/password_file.c",
        "src/persist_read.c",
        "src/persist_read_v234.c",
        "src/persist_read_v5.c",
        "src/persist_write.c",
        "src/persist_write_v5.c",
        "src/plugin_acl_check.c",
        "src/plugin_basic_auth.c",
        "src/plugin_callbacks.c",
        "src/plugin_cleanup.c",
        "src/plugin_client_offline.c",
        "src/plugin_connect.c",
        "src/plugin_disconnect.c",
        "src/plugin_extended_auth.c",
        "src/plugin_init.c",
        "src/plugin_message.c",
        "src/plugin_persist.c",
        "src/plugin_psk_key.c",
        "src/plugin_public.c",
        "src/plugin_reload.c",
        "src/plugin_subscribe.c",
        "src/plugin_tick.c",
        "src/plugin_unsubscribe.c",
        "src/plugin_v2.c",
        "src/plugin_v3.c",
        "src/plugin_v4.c",
        "src/plugin_v5.c",
        "src/property_broker.c",
        "src/proxy_v1.c",
        "src/proxy_v2.c",
        "src/psk_file.c",
        "src/read_handle.c",
        "src/retain.c",
        "src/security_default.c",
        "src/send_auth.c",
        "src/send_connack.c",
        "src/send_suback.c",
        "src/send_unsuback.c",
        "src/service.c",
        "src/session_expiry.c",
        "src/signals.c",
        "src/subs.c",
        "src/sys_tree.c",
        "src/topic_tok.c",
        "src/watchdog.c",
        "src/websockets.c",
        "src/will_delay.c",
        "src/xtreport.c",
    };

    // construct build arguments
    var mosquitto_flags: std.ArrayList([]const u8) = .empty;
    defer mosquitto_flags.deinit(alloc);

    // optional flags
    if (with_tls) {
        try mosquitto_flags.append(alloc, "-DWITH_TLS");
    }

    // common flags
    try mosquitto_flags.append(alloc, "-DWITH_BRIDGE");
    try mosquitto_flags.append(alloc, "-DWITH_BROKER");
    try mosquitto_flags.append(alloc, "-DWITH_PERSISTENCE");
    // try mosquitto_flags.append(alloc, "-DWITH_SQLITE");
    // try mosquitto_flags.append(alloc, "-DWITH_HTTP_API");

    // version
    const version_flag = try std.fmt.allocPrint(alloc, "-DVERSION=\"{s}\"", .{version});
    defer alloc.free(version_flag);
    try mosquitto_flags.append(alloc, version_flag);

    try mosquitto_flags.append(alloc, "-Wall");
    try mosquitto_flags.append(alloc, "-W");

    for (mosquitto_sources) |src| {
        mosquitto.root_module.addCSourceFile(.{ .file = mosquitto_dep.path(src), .flags = mosquitto_flags.items });
    }
    mosquitto.root_module.link_libc = true;

    // Export the broker's global symbols into the dynamic symbol table so that
    // plugins loaded at runtime via dlopen() can resolve broker API functions
    // (e.g. mosquitto_broker_publish_copy, mosquitto_callback_register). Without
    // -rdynamic these symbols live only in the regular symbol table and the
    // dynamic loader reports "undefined symbol" when loading a plugin .so.
    mosquitto.rdynamic = true;

    b.installArtifact(mosquitto);

    // -------------------------------------------------------------------------
    // Plugins — built as loadable shared libraries (.so / .dylib)
    // libcommon sources are compiled directly into each plugin to avoid a
    // runtime dependency on a separate libmosquitto_common.so.
    // -------------------------------------------------------------------------

    // libcommon split by external dependency:
    // core: no special deps beyond mosquitto headers — safe for every plugin
    const libcommon_core_sources = [_][]const u8{
        "libcommon/base64_common.c",
        "libcommon/file_common.c",
        "libcommon/memory_common.c",
        "libcommon/mqtt_common.c",
        "libcommon/property_common.c",
        "libcommon/strings_common.c",
        "libcommon/time_common.c",
        "libcommon/topic_common.c",
        "libcommon/utf8_common.c",
    };
    // json: requires <cjson/cJSON.h> — only include when cJSON is compiled in
    const libcommon_json_sources = [_][]const u8{
        "common/json_help.c",
        "libcommon/cjson_common.c",
    };
    // crypto: guarded by #ifdef WITH_TLS — only include when OpenSSL is linked
    const libcommon_crypto_sources = [_][]const u8{
        "libcommon/password_common.c",
        "libcommon/random_common.c",
    };
    // combined sets used per plugin
    const libcommon_full_sources = libcommon_core_sources ++ libcommon_json_sources ++ libcommon_crypto_sources;
    const libcommon_json_only_sources = libcommon_core_sources ++ libcommon_json_sources;
    const libcommon_crypto_only_sources = libcommon_core_sources ++ libcommon_crypto_sources;

    var plugin_flags: std.ArrayList([]const u8) = .empty;
    defer plugin_flags.deinit(alloc);
    if (with_tls) {
        try plugin_flags.append(alloc, "-DWITH_TLS");
    }
    const plugin_version_flag = try std.fmt.allocPrint(alloc, "-DVERSION=\"{s}\"", .{version});
    defer alloc.free(plugin_version_flag);
    try plugin_flags.append(alloc, plugin_version_flag);
    try plugin_flags.append(alloc, "-Wall");
    try plugin_flags.append(alloc, "-W");
    // Flags for plugins that do not need TLS/crypto (no -DWITH_TLS → OpenSSL
    // headers are not needed, password_common.c compiles as a no-op stub).
    var plugin_flags_notls: std.ArrayList([]const u8) = .empty;
    defer plugin_flags_notls.deinit(alloc);
    try plugin_flags_notls.append(alloc, plugin_version_flag);
    try plugin_flags_notls.append(alloc, "-Wall");
    try plugin_flags_notls.append(alloc, "-W");

    if (with_dynamic_security) {
        b.installArtifact(buildPlugin(
            b,
            "mosquitto_dynamic_security",
            mosquitto_dep,
            "plugins/dynamic-security",
            cjson_dep,
            &copy_cjson.step,
            null,
            target,
            optimize,
            &libcommon_full_sources,
            &[_][]const u8{
                "plugins/dynamic-security/acl.c",
                "plugins/dynamic-security/auth.c",
                "plugins/dynamic-security/clientlist.c",
                "plugins/dynamic-security/clients.c",
                "plugins/dynamic-security/config.c",
                "plugins/dynamic-security/config_init.c",
                "plugins/dynamic-security/control.c",
                "plugins/dynamic-security/default_acl.c",
                "plugins/dynamic-security/details.c",
                "plugins/dynamic-security/grouplist.c",
                "plugins/dynamic-security/groups.c",
                "plugins/dynamic-security/kicklist.c",
                "plugins/dynamic-security/plugin.c",
                "plugins/dynamic-security/rolelist.c",
                "plugins/dynamic-security/roles.c",
                "plugins/dynamic-security/tick.c",
            },
            plugin_flags.items,
            opt_libssl,
            opt_libcrypto,
        ));
    }

    if (with_persist_sqlite) {
        b.installArtifact(buildPlugin(
            b,
            "mosquitto_persist_sqlite",
            mosquitto_dep,
            "plugins/persist-sqlite",
            cjson_dep,       // persist-sqlite uses <cjson/cJSON.h>
            &copy_cjson.step,
            sqlite_dep,
            target,
            optimize,
            &libcommon_json_only_sources,
            &[_][]const u8{
                "plugins/persist-sqlite/base_msgs.c",
                "plugins/persist-sqlite/client_msgs.c",
                "plugins/persist-sqlite/clients.c",
                "plugins/persist-sqlite/common.c",
                "plugins/persist-sqlite/init.c",
                "plugins/persist-sqlite/plugin.c",
                "plugins/persist-sqlite/restore.c",
                "plugins/persist-sqlite/retain_msgs.c",
                "plugins/persist-sqlite/subscriptions.c",
                "plugins/persist-sqlite/tick.c",
                "plugins/persist-sqlite/will.c",
            },
            plugin_flags_notls.items,  // no password/TLS needed
            null,                      // no OpenSSL
            null,
        ));
    }

    if (with_acl_file_plugin) {
        b.installArtifact(buildPlugin(
            b,
            "mosquitto_acl_file",
            mosquitto_dep,
            "plugins/acl-file",
            null,              // no cJSON.c compilation needed
            &copy_cjson.step,  // still needed: mosquitto.h -> libcommon_cjson.h -> cjson/cJSON.h
            null,
            target,
            optimize,
            &libcommon_core_sources,
            &[_][]const u8{
                "plugins/acl-file/acl_check.c",
                "plugins/acl-file/acl_parse.c",
                "plugins/acl-file/plugin.c",
            },
            plugin_flags_notls.items,  // no password/TLS needed
            null,                      // no OpenSSL
            null,
        ));
    }

    if (with_password_file_plugin) {
        b.installArtifact(buildPlugin(
            b,
            "mosquitto_password_file",
            mosquitto_dep,
            "plugins/password-file",
            null,              // no cJSON.c compilation needed
            &copy_cjson.step,  // still needed: mosquitto.h -> libcommon_cjson.h -> cjson/cJSON.h
            null,
            target,
            optimize,
            &libcommon_crypto_only_sources,  // needs password_common + random_common
            &[_][]const u8{
                "plugins/password-file/password_check.c",
                "plugins/password-file/password_parse.c",
                "plugins/password-file/plugin.c",
            },
            plugin_flags.items,  // -DWITH_TLS enables password hashing
            opt_libssl,
            opt_libcrypto,
        ));
    }

    if (with_sparkplug_aware) {
        b.installArtifact(buildPlugin(
            b,
            "mosquitto_sparkplug_aware",
            mosquitto_dep,
            "plugins/sparkplug-aware",
            null,              // no cJSON.c compilation needed
            &copy_cjson.step,  // still needed: mosquitto.h -> libcommon_cjson.h -> cjson/cJSON.h
            null,
            target,
            optimize,
            &libcommon_core_sources,
            &[_][]const u8{
                "plugins/sparkplug-aware/on_message.c",
                "plugins/sparkplug-aware/plugin.c",
            },
            plugin_flags_notls.items,  // no password/TLS needed
            null,                      // no OpenSSL
            null,
        ));
    }
}

fn buildPlugin(
    b: *std.Build,
    name: []const u8,
    mosquitto_dep: *std.Build.Dependency,
    plugin_dir: []const u8,
    opt_cjson_dep: ?*std.Build.Dependency, // null = only need headers, don't compile cJSON.c
    copy_cjson_step: *std.Build.Step,      // always needed: mosquitto.h -> libcommon_cjson.h -> cjson/cJSON.h
    opt_sqlite_dep: ?*std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    libcommon_sources: []const []const u8,
    plugin_sources: []const []const u8,
    flags: []const []const u8,
    opt_libssl: ?*std.Build.Step.Compile,
    opt_libcrypto: ?*std.Build.Step.Compile,
) *std.Build.Step.Compile {
    const plugin = b.addLibrary(.{
        .name = name,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .dynamic,
    });
    plugin.root_module.addIncludePath(mosquitto_dep.path(""));
    plugin.root_module.addIncludePath(mosquitto_dep.path("include"));
    plugin.root_module.addIncludePath(mosquitto_dep.path("src"));
    plugin.root_module.addIncludePath(mosquitto_dep.path("libcommon"));
    plugin.root_module.addIncludePath(mosquitto_dep.path("common"));
    plugin.root_module.addIncludePath(mosquitto_dep.path("deps"));
    plugin.root_module.addIncludePath(mosquitto_dep.path(plugin_dir));
    // mosquitto.h pulls in mosquitto/libcommon_cjson.h which needs <cjson/cJSON.h>.
    // b.path(".") provides that via the cjson/ subdirectory created by copy_cjson_step.
    plugin.root_module.addIncludePath(b.path("."));
    plugin.step.dependOn(copy_cjson_step);
    if (opt_cjson_dep) |cjson_dep| {
        // Compile cJSON.c only for plugins that actively call the cJSON API.
        plugin.root_module.addIncludePath(cjson_dep.path(""));
        plugin.root_module.addCSourceFile(.{ .file = cjson_dep.path("cJSON.c"), .flags = &.{} });
    }
    // broker API symbols (e.g. mosquitto_callback_register) are resolved at
    // runtime when the plugin is dlopen'd by mosquitto — allow them to be
    // undefined at link time.
    plugin.linker_allow_shlib_undefined = true;
    if (opt_sqlite_dep) |sqlite_dep| {
        plugin.root_module.addIncludePath(sqlite_dep.path("."));
        plugin.root_module.addCSourceFile(.{ .file = sqlite_dep.path("sqlite3.c"), .flags = &.{} });
    }
    if (opt_libssl) |libssl| {
        plugin.root_module.linkLibrary(libssl);
        plugin.root_module.linkLibrary(opt_libcrypto.?);
        plugin.root_module.addIncludePath(libssl.getEmittedIncludeTree());
    }
    for (libcommon_sources) |src| {
        plugin.root_module.addCSourceFile(.{ .file = mosquitto_dep.path(src), .flags = flags });
    }
    for (plugin_sources) |src| {
        plugin.root_module.addCSourceFile(.{ .file = mosquitto_dep.path(src), .flags = flags });
    }
    plugin.root_module.link_libc = true;
    return plugin;
}

fn buildMicrohttpd(
    b: *std.Build,
    dep: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "microhttpd",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });

    lib.root_module.addIncludePath(dep.path("src/include"));
    lib.root_module.addIncludePath(dep.path("src/microhttpd"));
    // MHD_config.h lives alongside build.zig
    lib.root_module.addIncludePath(b.path("."));

    const mhd_flags: []const []const u8 = &.{
        "-std=gnu11",
        "-D_GNU_SOURCE",
        "-DBUILDING_MHD_LIB=1",
        "-DHAVE_POSTPROCESSOR=1",
        "-DHAVE_ANYAUTH=1",
        "-DBAUTH_SUPPORT=1",
        "-DDAUTH_SUPPORT=1",
        "-DCOOKIE_SUPPORT=1",
        "-W",
        "-Wall",
        "-Wno-missing-field-initializers",
        "-Wno-unused-parameter",
        "-Wno-sign-compare",
        "-Wno-tautological-constant-out-of-range-compare",
        "-Wno-shorten-64-to-32",
        "-Wno-implicit-int-conversion",
    };

    const core_sources = [_][]const u8{
        "src/microhttpd/connection.c",
        "src/microhttpd/reason_phrase.c",
        "src/microhttpd/daemon.c",
        "src/microhttpd/internal.c",
        "src/microhttpd/memorypool.c",
        "src/microhttpd/mhd_mono_clock.c",
        "src/microhttpd/mhd_str.c",
        "src/microhttpd/mhd_send.c",
        "src/microhttpd/mhd_sockets.c",
        "src/microhttpd/mhd_itc.c",
        "src/microhttpd/mhd_compat.c",
        "src/microhttpd/mhd_panic.c",
        "src/microhttpd/mhd_threads.c",
        "src/microhttpd/response.c",
        "src/microhttpd/tsearch.c",
        "src/microhttpd/postprocessor.c",
        "src/microhttpd/gen_auth.c",
        "src/microhttpd/basicauth.c",
        "src/microhttpd/digestauth.c",
        "src/microhttpd/md5.c",
        "src/microhttpd/sha256.c",
        "src/microhttpd/sha512_256.c",
        "src/microhttpd/sha1.c",
    };

    for (core_sources) |src| {
        lib.root_module.addCSourceFile(.{
            .file = dep.path(src),
            .flags = mhd_flags,
        });
    }

    lib.root_module.link_libc = true;
    return lib;
}