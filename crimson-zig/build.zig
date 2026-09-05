const std = @import("std");

pub fn build(b: *std.Build) void {
    const zemscripten = b.lazyImport(@This(), "zemscripten").?;
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const msgpack_dep = b.dependency("msgpack", .{
        .target = target,
        .optimize = optimize,
    });
    const raylib_dep = b.dependency("raylib_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const raylib_module = raylib_dep.module("raylib");
    const raylib_artifact = raylib_dep.artifact("raylib");

    const mod = b.addModule("crimson_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "msgpack", .module = msgpack_dep.module("msgpack") },
        },
    });

    const exe = b.addExecutable(.{
        .name = "crimson-zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "crimson_zig", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    const window_exe = b.addExecutable(.{
        .name = "crimson-zig-window",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/window_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "raylib", .module = raylib_module },
                .{ .name = "crimson_zig", .module = mod },
            },
        }),
    });
    window_exe.root_module.linkLibrary(raylib_artifact);
    b.installArtifact(window_exe);
    const window_step = b.step("window", "Build raylib desktop playable slice");
    window_step.dependOn(&window_exe.step);

    const quest_dump_exe = b.addExecutable(.{
        .name = "crimson-zig-quest-spawn-dump",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/quest_spawn/dump_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "crimson_zig", .module = mod },
            },
        }),
    });
    b.installArtifact(quest_dump_exe);

    const run_step = b.step("run", "Run crimson-zig CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_window_step = b.step("run-window", "Run raylib desktop playable slice");
    const run_window_cmd = b.addRunArtifact(window_exe);
    run_window_step.dependOn(&run_window_cmd.step);
    if (b.args) |args| {
        run_window_cmd.addArgs(args);
    }

    const asset_smoke_exe = b.addExecutable(.{
        .name = "crimson-zig-asset-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/asset_smoke_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "raylib", .module = raylib_module },
                .{ .name = "crimson_zig", .module = mod },
            },
        }),
    });
    b.installArtifact(asset_smoke_exe);
    const asset_smoke_step = b.step("asset-smoke", "Run local runtime asset decode smoke");
    const asset_smoke_cmd = b.addRunArtifact(asset_smoke_exe);
    asset_smoke_step.dependOn(&asset_smoke_cmd.step);
    if (b.args) |args| {
        asset_smoke_cmd.addArgs(args);
    }

    const asset_extract_exe = b.addExecutable(.{
        .name = "crimson-zig-asset-extract",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/asset_extract_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "raylib", .module = raylib_module },
                .{ .name = "crimson_zig", .module = mod },
            },
        }),
    });
    asset_extract_exe.root_module.linkLibrary(raylib_artifact);
    b.installArtifact(asset_extract_exe);
    const asset_extract_step = b.step("asset-extract", "Extract PAQ archives into an asset directory");
    const asset_extract_cmd = b.addRunArtifact(asset_extract_exe);
    asset_extract_step.dependOn(&asset_extract_cmd.step);
    if (b.args) |args| {
        asset_extract_cmd.addArgs(args);
    }

    const web_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .emscripten,
    });

    const web_raylib_dep = b.dependency("raylib_zig", .{
        .target = web_target,
        .optimize = optimize,
    });
    const web_raylib_module = web_raylib_dep.module("raylib");
    const web_raylib_artifact = web_raylib_dep.artifact("raylib");

    const web_window_lib = b.addLibrary(.{
        .name = "crimson-zig-window-web",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/window_main.zig"),
            .target = web_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "raylib", .module = web_raylib_module },
                .{ .name = "crimson_zig", .module = mod },
            },
        }),
    });
    web_window_lib.root_module.linkLibrary(web_raylib_artifact);

    const emsdk_dep = b.dependency("emsdk", .{});
    const emscripten_sysroot_include = emsdk_dep.path("upstream/emscripten/cache/sysroot/include");
    web_raylib_artifact.root_module.addIncludePath(emscripten_sysroot_include);
    web_window_lib.root_module.addIncludePath(emscripten_sysroot_include);

    var web_emcc_flags = zemscripten.emccDefaultFlags(b.allocator, .{
        .optimize = optimize,
        .fsanitize = true,
    });
    web_emcc_flags.put("-sASYNCIFY", {}) catch unreachable;

    var web_emcc_settings = zemscripten.emccDefaultSettings(b.allocator, .{
        .optimize = optimize,
        .emsdk_allocator = .emmalloc,
    });
    web_emcc_settings.put("FULL_ES3", "1") catch unreachable;
    web_emcc_settings.put("USE_GLFW", "3") catch unreachable;

    const activate_emsdk_step = zemscripten.activateEmsdkStep(b);
    const web_install_dir: std.Build.InstallDir = .{ .custom = "web" };
    const web_emcc_step = zemscripten.emccStep(b, web_window_lib, .{
        .optimize = optimize,
        .flags = web_emcc_flags,
        .settings = web_emcc_settings,
        .shell_file_path = emsdk_dep.path("upstream/emscripten/src/shell.html"),
        .out_file_name = "crimson-zig-window.html",
        .install_dir = web_install_dir,
    });
    web_emcc_step.dependOn(activate_emsdk_step);

    const web_window_step = b.step("web-window", "Build raylib window app for wasm32-emscripten");
    web_window_step.dependOn(web_emcc_step);

    const run_web_window_step = b.step("run-web-window", "Serve raylib web window app with emrun");
    const run_web_window_cmd = zemscripten.emrunStep(
        b,
        b.getInstallPath(web_install_dir, "crimson-zig-window.html"),
        &.{"--no_browser"},
    );
    run_web_window_cmd.dependOn(web_emcc_step);
    run_web_window_step.dependOn(run_web_window_cmd);

    const run_quest_dump_step = b.step("quest-spawn-dump", "Run quest spawn dump tool");
    const run_quest_dump_cmd = b.addRunArtifact(quest_dump_exe);
    run_quest_dump_cmd.step.dependOn(b.getInstallStep());
    run_quest_dump_step.dependOn(&run_quest_dump_cmd.step);
    if (b.args) |args| {
        run_quest_dump_cmd.addArgs(args);
    }

    const test_root_module = b.createModule(.{
        .root_source_file = b.path("src/test_root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "crimson_zig", .module = mod },
            .{ .name = "msgpack", .module = msgpack_dep.module("msgpack") },
            .{ .name = "raylib", .module = raylib_module },
        },
    });
    const mod_tests = b.addTest(.{ .root_module = test_root_module });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const root_lib_test_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "msgpack", .module = msgpack_dep.module("msgpack") },
        },
    });
    const root_lib_tests = b.addTest(.{ .root_module = root_lib_test_module });
    const run_root_lib_tests = b.addRunArtifact(root_lib_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_root_lib_tests.step);

    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    const wasm_module = b.createModule(.{
        .root_source_file = b.path("src/wasm_main.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "crimson_zig", .module = mod },
            .{ .name = "msgpack", .module = msgpack_dep.module("msgpack") },
        },
    });

    const wasm_exe = b.addExecutable(.{
        .name = "crimson-zig-wasm",
        .root_module = wasm_module,
    });
    wasm_exe.entry = .disabled;
    wasm_exe.rdynamic = true;
    wasm_exe.export_memory = true;

    const install_wasm = b.addInstallArtifact(wasm_exe, .{});
    const wasm_step = b.step("wasm", "Build wasm32-freestanding runtime ABI module");
    wasm_step.dependOn(&install_wasm.step);
}
