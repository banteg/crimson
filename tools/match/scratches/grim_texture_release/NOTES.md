# grim_texture_release

The native body is the `GrimTexture` destructor. It releases the live D3D
texture and backup COM resources, deletes the owned name buffer, and nulls all
three pointers.
