const rl = @import("raylib");

pub fn main() !void {
    rl.initWindow(960, 540, "crimson-zig");
    defer rl.closeWindow();

    rl.setTargetFPS(60);

    while (!rl.windowShouldClose()) {
        rl.beginDrawing();
        defer rl.endDrawing();

        rl.clearBackground(rl.Color.black);
    }
}
