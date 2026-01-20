var grim_interface_offset = 0x8083c;
var grim_interface_ptr_addr = null;
var grim_interface = NULL;
var vtable = NULL;

var last_color = { r: 0, g: 0, b: 0, a: 0 };

function get_crimsonland_base() {
    var mod = Process.findModuleByName("crimsonland.exe");
    if (mod) return mod.base;
    return ptr(0x400000); // Fallback
}

function read_grim_interface() {
    try {
        if (!grim_interface_ptr_addr) {
            var base = get_crimsonland_base();
            grim_interface_ptr_addr = base.add(grim_interface_offset);
            console.log("Grim Interface Ptr Addr: " + grim_interface_ptr_addr);
        }
        var ptr_val = Memory.readPointer(grim_interface_ptr_addr);
        if (ptr_val.isNull()) {
            return false;
        }
        grim_interface = ptr_val;
        vtable = Memory.readPointer(grim_interface);
        return true;
    } catch (e) {
        console.log("Error reading grim interface: " + e);
        return false;
    }
}

function hook_functions() {
    if (!read_grim_interface()) {
        console.log("Waiting for grim_interface...");
        setTimeout(hook_functions, 1000);
        return;
    }

    console.log("Grim Interface found at: " + grim_interface);
    console.log("VTable found at: " + vtable);

    // grim_set_color (0x114)
    var set_color_addr = Memory.readPointer(vtable.add(0x114));
    Interceptor.attach(set_color_addr, {
        onEnter: function(args) {
            this.r = Memory.readFloat(this.context.esp.add(4));
            this.g = Memory.readFloat(this.context.esp.add(8));
            this.b = Memory.readFloat(this.context.esp.add(12));
            this.a = Memory.readFloat(this.context.esp.add(16));
            
            last_color = { r: this.r, g: this.g, b: this.b, a: this.a };
        }
    });

    // grim_draw_text_mono (0x13c)
    var draw_mono_addr = Memory.readPointer(vtable.add(0x13c));
    Interceptor.attach(draw_mono_addr, {
        onEnter: function(args) {
            var text_ptr = Memory.readPointer(this.context.esp.add(12));
            if (!text_ptr.isNull()) {
                try {
                    var text = text_ptr.readUtf8String();
                    // Filter for quest titles or level info
                    if (text && (text.includes("Land Hostile") || text.match(/^\d+\.\d+$/))) {
                        console.log("[DrawMono] Text: '" + text + "' Color: " + JSON.stringify(last_color));
                    }
                } catch(e) {}
            }
        }
    });

    // grim_draw_text_mono_fmt (0x140)
    var draw_mono_fmt_addr = Memory.readPointer(vtable.add(0x140));
    Interceptor.attach(draw_mono_fmt_addr, {
        onEnter: function(args) {
            // Check first few stack args for strings
            for (var i = 0; i < 4; i++) {
                try {
                    var ptr_val = Memory.readPointer(this.context.esp.add(4 + i * 4));
                    if (!ptr_val.isNull()) {
                         var str = ptr_val.readUtf8String();
                         if (str && (str.includes("Land Hostile") || str.includes("%d.%d") || str.match(/^\d+\.\d+$/))) {
                             console.log("[DrawMonoFmt] Arg" + i + ": '" + str + "' Color: " + JSON.stringify(last_color));
                         }
                    }
                } catch (e) { }
            }
        }
    });
    
    console.log("Hooks installed. Waiting for quest screen draw...");
}

hook_functions();