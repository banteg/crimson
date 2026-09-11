  if (CONFIG.enableInputHooks) {
    function addInputQueryHook(name, queryKey, token) {
      attachHook(name, fnPtrs[name], {
        onEnter() {
          const callerStatic = runtimeToStatic(this.returnAddress);
          pushInputContext(this.threadId, {
            query_key: queryKey,
            token: token,
            query: name,
            arg0: null,
            caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
            caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
            backtrace: maybeBacktrace(this.context),
          });
        },
        onLeave(retval) {
          const ctx = popInputContext(this.threadId);
          if (!ctx) return;
          let pressed = false;
          try {
            pressed = retval.toInt32() !== 0;
          } catch (_) {
            pressed = false;
          }
          const payload = {
            query: name,
            pressed: pressed,
            arg0: null,
            caller: ctx.caller,
            caller_static: ctx.caller_static,
            backtrace: ctx.backtrace,
            console_open: readDataU32("console_open_flag"),
            primary_latch: readDataU32("input_primary_latch"),
          };
          const tick = outState.currentTick;
          if (tick) {
            const state = ensurePlayerKeyState(tick, 0);
            if (state) {
              if (ctx.query_key === "primary_down") {
                state.fire_down = state.fire_down === true ? true : !!pressed;
              }
              if (ctx.query_key === "primary_edge") {
                state.fire_pressed = state.fire_pressed === true ? true : !!pressed;
              }
            }
          }
          registerInputQuery(ctx.query_key, pressed, ctx.token, payload);
          emitRawEvent(Object.assign({ event: name }, payload));
        },
      });
    }

    addInputQueryHook("input_primary_just_pressed", "primary_edge", "ipj");
    addInputQueryHook("input_primary_is_down", "primary_down", "ipd");
    addInputQueryHook("input_any_key_pressed", "any_key", "iak");

    function addGrimInputQueryHook(name, ptrVal, classifyKind, tokenPrefix) {
      attachHook(name, ptrVal, {
        onEnter(args) {
          let arg0 = null;
          try {
            arg0 = args[0] ? args[0].toInt32() : null;
          } catch (_) {
            arg0 = null;
          }
          const callerStatic = runtimeToStatic(this.returnAddress);
          if (!isPlayerUpdateCaller(callerStatic == null ? null : toHex(callerStatic, 8))) {
            return;
          }
          pushInputContext(this.threadId, {
            query_key: null,
            token: null,
            query: name,
            arg0: arg0,
            caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
            caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
            backtrace: maybeBacktrace(this.context),
          });
        },
        onLeave(retval) {
          const ctx = popInputContext(this.threadId);
          if (!ctx) return;
          let pressed = false;
          try {
            pressed = retval.toInt32() !== 0;
          } catch (_) {
            pressed = false;
          }
          const queryKey = classifyKind(ctx.arg0);
          updatePlayerInputKeyState(outState.currentTick, name, ctx.arg0, pressed, ctx.caller_static);
          if (!queryKey) return;
          const payload = {
            query: name,
            pressed: pressed,
            arg0: ctx.arg0,
            caller: ctx.caller,
            caller_static: ctx.caller_static,
            backtrace: ctx.backtrace,
            console_open: readDataU32("console_open_flag"),
            primary_latch: readDataU32("input_primary_latch"),
          };
          const token = tokenPrefix + ":" + String(ctx.arg0 == null ? "na" : ctx.arg0);
          registerInputQuery(queryKey, pressed, token, payload);
          emitRawEvent(Object.assign({ event: name }, payload));
        },
      });
    }

    addGrimInputQueryHook(
      "grim_is_key_down",
      grimFnPtrs.grim_is_key_down,
      function (keyCode) {
        return null;
      },
      "gikd"
    );
    addGrimInputQueryHook(
      "grim_is_key_active",
      grimFnPtrs.grim_is_key_active,
      function (keyCode) {
        return null;
      },
      "gika"
    );
  }

