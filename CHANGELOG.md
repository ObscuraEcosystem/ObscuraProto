## 1.0.2
- Added `set_on_open_callback` / `set_on_close_callback` to `WsServerWrapper` — connection lifecycle callbacks that fire on WebSocket open and close events.
- Added server-side `SO_REUSEADDR` (`set_reuse_addr(true)`) to prevent "Address already in use" errors on rapid restart.
