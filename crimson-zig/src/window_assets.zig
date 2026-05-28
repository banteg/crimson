const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const runtime_archive = @import("runtime_archive.zig");
const runtime_paths = cz.runtime_paths;

pub const paq_name = "crimson.paq";
pub const small_font_widths_path = "load/smallFnt.dat";

pub const TextureId = enum {
    backplasma,
    mockup,
    logo_esrb,
    loading,
    cl_logo,
    splash_10tons,
    splash_reflexive,
    default_font_courier,
    small_white,
    trooper,
    zombie,
    spider_sp1,
    spider_sp2,
    alien,
    lizard,
    arrow,
    bullet_i,
    bullet_trail,
    bodyset,
    projs,
    ui_icon_aim,
    ui_button_sm,
    ui_button_md,
    ui_check_on,
    ui_check_off,
    ui_rect_off,
    ui_rect_on,
    bonuses,
    ui_ind_bullet,
    ui_ind_rocket,
    ui_ind_electric,
    ui_ind_fire,
    particles,
    ui_ind_life,
    ui_ind_panel,
    ui_arrow,
    ui_cursor,
    ui_aim,
    ter_q1_base,
    ter_q1_overlay,
    ter_q2_base,
    ter_q2_overlay,
    ter_q3_base,
    ter_q3_overlay,
    ter_q4_base,
    ter_q4_overlay,
    ui_text_level_complete,
    ui_text_quest,
    ui_num1,
    ui_num2,
    ui_num3,
    ui_num4,
    ui_num5,
    ui_wicons,
    ui_game_top,
    ui_life_heart,
    ui_clock_table,
    ui_clock_pointer,
    muzzle_flash,
    ui_drop_on,
    ui_drop_off,
    ui_sign_crimson,
    ui_menu_item,
    ui_menu_panel,
    ui_item_texts,
    ui_text_reaper,
    ui_text_well_done,
    ui_text_controls,
    ui_text_pick_a_perk,
    ui_text_level_up,
};

pub const TextureSpec = struct {
    rel_path: []const u8,
    clamp: bool = false,
    point_filter: bool = false,
};

pub const AssetFormat = enum {
    jaz,
    tga,
    jpg,
    jpeg,
    dat,
    unsupported,
};

pub const TextureAsset = struct {
    format: AssetFormat,
    payload: []const u8,
};

pub const AssetArchiveError = runtime_archive.RuntimeArchiveError;

pub const DecodeImageError = formats.jaz.JazError || formats.tga.TgaError || std.mem.Allocator.Error || rl.RaylibError || error{
    InvalidImageDimensions,
    UnsupportedTextureFormat,
};

pub const LoadRuntimeAssetsError = AssetArchiveError ||
    DecodeImageError ||
    std.Io.Dir.AccessError ||
    std.Io.Dir.ReadFileAllocError ||
    std.process.Environ.GetAllocError ||
    error{
        MissingTextureAsset,
        MissingFontWidths,
    };

pub const AssetArchive = runtime_archive.Archive;

pub const RuntimeAssets = struct {
    allocator: std.mem.Allocator,
    assets_dir: []u8,
    textures: [texture_count]rl.Texture2D,
    small_font_widths: []u8,
    archive_entry_count: usize,

    pub fn deinit(self: *RuntimeAssets) void {
        for (self.textures) |loaded_texture| {
            rl.unloadTexture(loaded_texture);
        }
        self.allocator.free(self.small_font_widths);
        self.allocator.free(self.assets_dir);
        self.* = undefined;
    }

    pub fn texture(self: *const RuntimeAssets, texture_id: TextureId) rl.Texture2D {
        return self.textures[@intFromEnum(texture_id)];
    }

    pub fn textureCount(self: *const RuntimeAssets) usize {
        _ = self;
        return texture_count;
    }
};

pub const texture_count = std.meta.fields(TextureId).len;

pub fn runtimeTextureSpec(texture_id: TextureId) TextureSpec {
    return textureSpec(texture_id);
}

pub fn detectAssetFormat(rel_path: []const u8) AssetFormat {
    if (std.ascii.endsWithIgnoreCase(rel_path, ".jaz")) return .jaz;
    if (std.ascii.endsWithIgnoreCase(rel_path, ".tga")) return .tga;
    if (std.ascii.endsWithIgnoreCase(rel_path, ".jpg")) return .jpg;
    if (std.ascii.endsWithIgnoreCase(rel_path, ".jpeg")) return .jpeg;
    if (std.ascii.endsWithIgnoreCase(rel_path, ".dat")) return .dat;
    return .unsupported;
}

pub fn decodeImageFromBytes(allocator: std.mem.Allocator, rel_path: []const u8, bytes: []const u8) DecodeImageError!rl.Image {
    return decodeImageFromAssetFormat(allocator, detectAssetFormat(rel_path), bytes);
}

pub fn decodeImageFromAssetFormat(allocator: std.mem.Allocator, format: AssetFormat, bytes: []const u8) DecodeImageError!rl.Image {
    return switch (format) {
        .jaz => decodeJazImage(allocator, bytes),
        .tga => decodeTgaImage(bytes),
        .jpg => rl.loadImageFromMemory(".jpg", bytes),
        .jpeg => rl.loadImageFromMemory(".jpeg", bytes),
        else => error.UnsupportedTextureFormat,
    };
}

pub fn loadRuntimeAssets(allocator: std.mem.Allocator, assets_dir: []const u8) LoadRuntimeAssetsError!RuntimeAssets {
    const owned_assets_dir = try allocator.dupe(u8, assets_dir);
    errdefer allocator.free(owned_assets_dir);

    const paq_path = try std.fs.path.join(allocator, &.{ assets_dir, paq_name });
    defer allocator.free(paq_path);

    var archive = try AssetArchive.fromPath(allocator, paq_path);
    defer archive.deinit();

    var textures: [texture_count]rl.Texture2D = undefined;
    errdefer {
        for (textures[0..]) |texture| {
            if (texture.id == 0) continue;
            rl.unloadTexture(texture);
        }
    }
    @memset(&textures, std.mem.zeroes(rl.Texture2D));

    inline for (std.meta.fields(TextureId)) |field| {
        const texture_id: TextureId = @enumFromInt(field.value);
        const spec = textureSpec(texture_id);
        const asset = selectTextureAsset(&archive, spec.rel_path) orelse return error.MissingTextureAsset;
        textures[field.value] = try loadTextureFromBytes(allocator, spec, asset);
    }

    const small_font_widths_blob = archive.get(small_font_widths_path) orelse return error.MissingFontWidths;
    const small_font_widths = try allocator.dupe(u8, small_font_widths_blob);
    errdefer allocator.free(small_font_widths);

    return .{
        .allocator = allocator,
        .assets_dir = owned_assets_dir,
        .textures = textures,
        .small_font_widths = small_font_widths,
        .archive_entry_count = archive.entryCount(),
    };
}

pub fn resolveRuntimeAssetsDir(allocator: std.mem.Allocator) LoadRuntimeAssetsError!?[]u8 {
    return runtime_paths.resolveArchiveDir(allocator, paq_name);
}

pub fn loadRuntimeAssetsFromDefaultSearch(allocator: std.mem.Allocator) LoadRuntimeAssetsError!?RuntimeAssets {
    const assets_dir = (try resolveRuntimeAssetsDir(allocator)) orelse return null;
    defer allocator.free(assets_dir);
    const assets = try loadRuntimeAssets(allocator, assets_dir);
    return assets;
}

pub fn selectTextureAsset(archive: *const AssetArchive, rel_path: []const u8) ?TextureAsset {
    if (std.ascii.endsWithIgnoreCase(rel_path, ".jaz")) {
        var alt_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const stem = rel_path[0 .. rel_path.len - 4];

        const tga_path = std.fmt.bufPrint(&alt_path_buffer, "{s}.tga", .{stem}) catch return null;
        if (archive.get(tga_path)) |payload| return .{ .format = .tga, .payload = payload };

        const jpg_path = std.fmt.bufPrint(&alt_path_buffer, "{s}.jpg", .{stem}) catch return null;
        if (archive.get(jpg_path)) |payload| return .{ .format = .jpg, .payload = payload };
    }

    const payload = archive.get(rel_path) orelse return null;
    return .{ .format = detectAssetFormat(rel_path), .payload = payload };
}

fn loadTextureFromBytes(allocator: std.mem.Allocator, spec: TextureSpec, asset: TextureAsset) DecodeImageError!rl.Texture2D {
    var image = try decodeImageFromAssetFormat(allocator, asset.format, asset.payload);
    defer image.unload();

    const texture = try rl.loadTextureFromImage(image);
    rl.setTextureFilter(texture, .bilinear);
    if (spec.clamp) rl.setTextureWrap(texture, .clamp);
    if (spec.point_filter) rl.setTextureFilter(texture, .point);
    return texture;
}

fn decodeJazImage(allocator: std.mem.Allocator, bytes: []const u8) DecodeImageError!rl.Image {
    var decoded = try formats.jaz.decode(allocator, bytes);
    defer decoded.deinit(allocator);

    var image = try rl.loadImageFromMemory(".jpg", decoded.jpeg_bytes);
    errdefer image.unload();

    if (image.width <= 0 or image.height <= 0) return error.InvalidImageDimensions;
    rl.imageFormat(&image, .uncompressed_r8g8b8a8);

    const pixel_count = @as(usize, @intCast(image.width * image.height));
    const alpha = try formats.jaz.decodeAlphaRle(allocator, decoded.alpha_rle_bytes, pixel_count);
    defer allocator.free(alpha);

    const pixels = @as([*]u8, @ptrCast(image.data))[0 .. pixel_count * 4];
    for (alpha, 0..) |alpha_value, idx| {
        pixels[idx * 4 + 3] = alpha_value;
    }

    return image;
}

fn decodeTgaImage(bytes: []const u8) DecodeImageError!rl.Image {
    const decoded = try formats.tga.decode(std.heap.c_allocator, bytes);
    return .{
        .data = @ptrCast(decoded.pixels_rgba.ptr),
        .width = decoded.width,
        .height = decoded.height,
        .mipmaps = 1,
        .format = .uncompressed_r8g8b8a8,
    };
}

fn textureSpec(texture_id: TextureId) TextureSpec {
    return switch (texture_id) {
        .backplasma => .{ .rel_path = "load/backplasma.jaz" },
        .mockup => .{ .rel_path = "load/mockup.jaz" },
        .logo_esrb => .{ .rel_path = "load/esrb_mature.jaz" },
        .loading => .{ .rel_path = "load/loading.jaz" },
        .cl_logo => .{ .rel_path = "load/logo_crimsonland.tga" },
        .splash_10tons => .{ .rel_path = "load/splash10tons.jaz" },
        .splash_reflexive => .{ .rel_path = "load/splashReflexive.jpg" },
        .default_font_courier => .{ .rel_path = "load/default_font_courier.tga" },
        .small_white => .{ .rel_path = "load/smallWhite.tga", .point_filter = true },
        .trooper => .{ .rel_path = "game/trooper.jaz" },
        .zombie => .{ .rel_path = "game/zombie.jaz" },
        .spider_sp1 => .{ .rel_path = "game/spider_sp1.jaz" },
        .spider_sp2 => .{ .rel_path = "game/spider_sp2.jaz" },
        .alien => .{ .rel_path = "game/alien.jaz" },
        .lizard => .{ .rel_path = "game/lizard.jaz" },
        .arrow => .{ .rel_path = "load/arrow.tga" },
        .bullet_i => .{ .rel_path = "load/bullet16.tga" },
        .bullet_trail => .{ .rel_path = "load/bulletTrail.tga" },
        .bodyset => .{ .rel_path = "game/bodyset.jaz" },
        .projs => .{ .rel_path = "game/projs.jaz" },
        .ui_icon_aim => .{ .rel_path = "ui/ui_iconAim.jaz", .clamp = true },
        .ui_button_sm => .{ .rel_path = "ui/ui_button_64x32.jaz", .clamp = true },
        .ui_button_md => .{ .rel_path = "ui/ui_button_128x32.jaz", .clamp = true },
        .ui_check_on => .{ .rel_path = "ui/ui_checkOn.jaz", .clamp = true },
        .ui_check_off => .{ .rel_path = "ui/ui_checkOff.jaz", .clamp = true },
        .ui_rect_off => .{ .rel_path = "ui/ui_rectOff.jaz", .clamp = true },
        .ui_rect_on => .{ .rel_path = "ui/ui_rectOn.jaz", .clamp = true },
        .bonuses => .{ .rel_path = "game/bonuses.jaz" },
        .ui_ind_bullet => .{ .rel_path = "ui/ui_indBullet.jaz", .clamp = true },
        .ui_ind_rocket => .{ .rel_path = "ui/ui_indRocket.jaz", .clamp = true },
        .ui_ind_electric => .{ .rel_path = "ui/ui_indElectric.jaz", .clamp = true },
        .ui_ind_fire => .{ .rel_path = "ui/ui_indFire.jaz", .clamp = true },
        .particles => .{ .rel_path = "game/particles.jaz" },
        .ui_ind_life => .{ .rel_path = "ui/ui_indLife.jaz", .clamp = true },
        .ui_ind_panel => .{ .rel_path = "ui/ui_indPanel.jaz", .clamp = true },
        .ui_arrow => .{ .rel_path = "ui/ui_arrow.jaz", .clamp = true },
        .ui_cursor => .{ .rel_path = "ui/ui_cursor.jaz", .clamp = true },
        .ui_aim => .{ .rel_path = "ui/ui_aim.jaz", .clamp = true },
        .ter_q1_base => .{ .rel_path = "ter/ter_q1_base.jaz" },
        .ter_q1_overlay => .{ .rel_path = "ter/ter_q1_tex1.jaz" },
        .ter_q2_base => .{ .rel_path = "ter/ter_q2_base.jaz" },
        .ter_q2_overlay => .{ .rel_path = "ter/ter_q2_tex1.jaz" },
        .ter_q3_base => .{ .rel_path = "ter/ter_q3_base.jaz" },
        .ter_q3_overlay => .{ .rel_path = "ter/ter_q3_tex1.jaz" },
        .ter_q4_base => .{ .rel_path = "ter/ter_q4_base.jaz" },
        .ter_q4_overlay => .{ .rel_path = "ter/ter_q4_tex1.jaz" },
        .ui_text_level_complete => .{ .rel_path = "ui/ui_textLevComp.jaz", .clamp = true },
        .ui_text_quest => .{ .rel_path = "ui/ui_textQuest.jaz", .clamp = true },
        .ui_num1 => .{ .rel_path = "ui/ui_num1.jaz", .clamp = true },
        .ui_num2 => .{ .rel_path = "ui/ui_num2.jaz", .clamp = true },
        .ui_num3 => .{ .rel_path = "ui/ui_num3.jaz", .clamp = true },
        .ui_num4 => .{ .rel_path = "ui/ui_num4.jaz", .clamp = true },
        .ui_num5 => .{ .rel_path = "ui/ui_num5.jaz", .clamp = true },
        .ui_wicons => .{ .rel_path = "ui/ui_wicons.jaz", .clamp = true },
        .ui_game_top => .{ .rel_path = "ui/ui_gameTop.jaz", .clamp = true },
        .ui_life_heart => .{ .rel_path = "ui/ui_lifeHeart.jaz", .clamp = true },
        .ui_clock_table => .{ .rel_path = "ui/ui_clockTable.jaz", .clamp = true },
        .ui_clock_pointer => .{ .rel_path = "ui/ui_clockPointer.jaz", .clamp = true },
        .muzzle_flash => .{ .rel_path = "game/muzzleFlash.jaz" },
        .ui_drop_on => .{ .rel_path = "ui/ui_dropDownOn.jaz", .clamp = true },
        .ui_drop_off => .{ .rel_path = "ui/ui_dropDownOff.jaz", .clamp = true },
        .ui_sign_crimson => .{ .rel_path = "ui/ui_signCrimson.jaz", .clamp = true },
        .ui_menu_item => .{ .rel_path = "ui/ui_menuItem.jaz", .clamp = true },
        .ui_menu_panel => .{ .rel_path = "ui/ui_menuPanel.jaz", .clamp = true },
        .ui_item_texts => .{ .rel_path = "ui/ui_itemTexts.jaz", .clamp = true },
        .ui_text_reaper => .{ .rel_path = "ui/ui_textReaper.jaz", .clamp = true },
        .ui_text_well_done => .{ .rel_path = "ui/ui_textWellDone.jaz", .clamp = true },
        .ui_text_controls => .{ .rel_path = "ui/ui_textControls.jaz", .clamp = true },
        .ui_text_pick_a_perk => .{ .rel_path = "ui/ui_textPickAPerk.jaz", .clamp = true },
        .ui_text_level_up => .{ .rel_path = "ui/ui_textLevelUp.jaz", .clamp = true },
    };
}

test "detect asset formats from extension" {
    try std.testing.expectEqual(AssetFormat.jaz, detectAssetFormat("ui/ui_button.jaz"));
    try std.testing.expectEqual(AssetFormat.tga, detectAssetFormat("load/logo.tga"));
    try std.testing.expectEqual(AssetFormat.jpg, detectAssetFormat("load/splash.jpg"));
    try std.testing.expectEqual(AssetFormat.jpeg, detectAssetFormat("load/splash.jpeg"));
    try std.testing.expectEqual(AssetFormat.dat, detectAssetFormat("load/smallFnt.dat"));
    try std.testing.expectEqual(AssetFormat.unsupported, detectAssetFormat("load/file.bin"));
}

test "decode image rejects unsupported extensions" {
    try std.testing.expectError(
        error.UnsupportedTextureFormat,
        decodeImageFromBytes(std.testing.allocator, "test.dat", "abc"),
    );
}

test "texture asset lookup prefers same-stem source art" {
    const allocator = std.testing.allocator;

    const encoded = try formats.paq.encode(allocator, &[_]formats.paq.EntryInput{
        .{ .name = "ui\\button.jaz", .payload = "old" },
        .{ .name = "ui/button.tga", .payload = "source" },
        .{ .name = "load/arrow.tga", .payload = "arrow" },
    });
    defer allocator.free(encoded);

    var archive = try AssetArchive.fromBytes(allocator, encoded);
    defer archive.deinit();

    const source_asset = selectTextureAsset(&archive, "ui/button.jaz").?;
    try std.testing.expectEqual(AssetFormat.tga, source_asset.format);
    try std.testing.expectEqualStrings("source", source_asset.payload);

    const direct_asset = selectTextureAsset(&archive, "load/arrow.tga").?;
    try std.testing.expectEqual(AssetFormat.tga, direct_asset.format);
    try std.testing.expectEqualStrings("arrow", direct_asset.payload);
}
