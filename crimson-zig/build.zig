const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const msgpack_dep = b.dependency("msgpack", .{
        .target = target,
        .optimize = optimize,
    });

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
        },
    });
    const mod_tests = b.addTest(.{ .root_module = test_root_module });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

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
    const wasm_step = b.step("wasm", "Build wasm32-freestanding verifier module");
    wasm_step.dependOn(&install_wasm.step);
}
