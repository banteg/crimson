# plugin_runtime_update_and_render

Native target: `crimsonland.exe` at `0x0040b630` (265 bytes).

This is the complete per-frame owner for a loaded CMOD interface. A missing
interface immediately transitions to the mods menu, renders the transition,
and rearms initialization. On first entry into plugin state it mutes the extra
track, clears gameplay pools, calls `Init()`, and clears `parms.onPause`.
Later frames call `Frame(frame_dt_ms)`; a zero result calls `Shutdown()`, mutes
the track, releases the DLL, clears both interface/module globals, and returns
to the mods menu. A nonzero result marks the runtime active.

The normal UI transition is rendered every live frame. The standard cursor is
always drawn while an untransitioned plugin state is current; outside that
case it is drawn only when a live plugin requests `parms.drawMouseCursor`.
