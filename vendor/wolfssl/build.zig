const std = @import("std");

fn sdkPath(comptime suffix: []const u8) []const u8 {
    if (suffix[0] != '/') @compileError("relToPath requires an absolute path!");
    return comptime blk: {
        const root_dir = std.fs.path.dirname(@src().file) orelse ".";
        break :blk root_dir ++ suffix;
    };
}

pub const include_dirs = [_][]const u8{
    "/vendor/wolfssl",
};

pub fn createWolfSSL(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = "wolfSSL",
        .target = target,
        .optimize = optimize,
    });
    //lib.setBuildMode(.ReleaseSafe);
    //lib.setTarget(target);
    lib.addCSourceFiles(.{
        .files = &wolfssl_sources,
        .flags = &wolfssl_flags
    });
    lib.addCSourceFiles(.{
        .files = &wolfcrypt_sources,
        .flags = &wolfcrypt_flags,
    });
    lib.addIncludePath(b.path("./vendor/wolfssl/vendor/wolfssl"));

    lib.defineCMacro("TFM_TIMING_RESISTANT", null);
    lib.defineCMacro("ECC_TIMING_RESISTANT", null);
    lib.defineCMacro("WC_RSA_BLINDING", null);
    lib.defineCMacro("HAVE_PTHREAD", null);
    lib.defineCMacro("NO_INLINE", null);
    lib.defineCMacro("WOLFSSL_TLS13", null);
    lib.defineCMacro("WC_RSA_PSS", null);
    lib.defineCMacro("HAVE_TLS_EXTENSIONS", null);
    lib.defineCMacro("HAVE_SNI", null);
    lib.defineCMacro("HAVE_MAX_FRAGMENT", null);
    lib.defineCMacro("HAVE_TRUNCATED_HMAC", null);
    lib.defineCMacro("HAVE_ALPN", null);
    lib.defineCMacro("HAVE_TRUSTED_CA", null);
    lib.defineCMacro("HAVE_HKDF", null);
    lib.defineCMacro("BUILD_GCM", null);
    lib.defineCMacro("HAVE_AESCCM", null);
    lib.defineCMacro("HAVE_SESSION_TICKET", null);
    lib.defineCMacro("HAVE_CHACHA", null);
    lib.defineCMacro("HAVE_POLY1305", null);
    lib.defineCMacro("HAVE_ECC", null);
    lib.defineCMacro("HAVE_FFDHE_2048", null);
    lib.defineCMacro("HAVE_FFDHE_3072", null);
    lib.defineCMacro("HAVE_FFDHE_4096", null);
    lib.defineCMacro("HAVE_FFDHE_6144", null);
    lib.defineCMacro("HAVE_FFDHE_8192", null);
    lib.defineCMacro("HAVE_ONE_TIME_AUTH", null);
    lib.defineCMacro("HAVE_SYS_TIME_H", null);
    lib.defineCMacro("SESSION_INDEX", null);
    lib.defineCMacro("SESSION_CERTS", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509_SMALL", null);
    lib.linkLibC();

    return lib;
}

const wolfssl_flags = [_][]const u8{
    "-std=c89",

    // Ignore errors error: incompatible integer to pointer conversion assigning to 'char *' from 'int'
    // Reference: https://github.com/fjebaker/wolfssl/blob/master/build.zig
    "-Wno-int-conversion",
};

const wolfssl_sources = [_][]const u8{
    "vendor/wolfssl/vendor/wolfssl/src/bio.c",
    "vendor/wolfssl/vendor/wolfssl/src/crl.c",
    "vendor/wolfssl/vendor/wolfssl/src/internal.c",
    "vendor/wolfssl/vendor/wolfssl/src/keys.c",
    "vendor/wolfssl/vendor/wolfssl/src/ocsp.c",
    "vendor/wolfssl/vendor/wolfssl/src/sniffer.c",
    "vendor/wolfssl/vendor/wolfssl/src/ssl.c",
    "vendor/wolfssl/vendor/wolfssl/src/tls.c",
    "vendor/wolfssl/vendor/wolfssl/src/tls13.c",
    "vendor/wolfssl/vendor/wolfssl/src/wolfio.c",
};

const wolfcrypt_flags = [_][]const u8{
    "-std=c89",

    // Ignore errors error: incompatible integer to pointer conversion assigning to 'char *' from 'int'
    // Reference: https://github.com/fjebaker/wolfssl/blob/master/build.zig
    "-Wno-int-conversion",
};
const wolfcrypt_sources = [_][]const u8{
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/aes.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/arc4.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/asm.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/asn.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/blake2b.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/blake2s.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/camellia.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/chacha.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/chacha20_poly1305.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/cmac.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/coding.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/compress.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/cpuid.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/cryptocb.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/curve448.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/curve25519.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/des3.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/dh.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/dsa.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/ecc.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/eccsi.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/ecc_fp.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/ed448.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/ed25519.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/error.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/evp.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/falcon.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/fe_448.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/fe_low_mem.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/fe_operations.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/ge_448.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/ge_low_mem.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/ge_operations.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/hash.c",
    // "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/hc128.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/hmac.c",
    // "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/idea.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/integer.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/kdf.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/logging.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/md2.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/md4.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/md5.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/memory.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/misc.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/pkcs7.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/pkcs12.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/poly1305.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/pwdbased.c",
    // "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/rabbit.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/random.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/rc2.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/ripemd.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/rsa.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sakke.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sha.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sha3.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sha256.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sha512.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/signature.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_arm32.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_arm64.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_armthumb.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_c32.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_c64.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_cortexm.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_dsp32.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_int.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/sp_x86_64.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/srp.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/tfm.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/wc_dsp.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/wc_encrypt.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/wc_pkcs11.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/wc_port.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/wolfevent.c",
    "vendor/wolfssl/vendor/wolfssl/wolfcrypt/src/wolfmath.c",
};
