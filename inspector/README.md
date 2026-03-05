# linux-mem-inspector

ReClass-inspired memory inspection tool for Linux with MCP support.

**Usage:** `inspector [pid]`  
Runs with or without a PID. Use **Process -> Attach...** in the UI to pick a process (from the list or by entering a PID). When attaching you can enable **Auto-connect by binary name** so the next launch re-attaches to that process. **Edit -> Settings** configures the MCP server and **Auto-connect executable name**. Config file: `$XDG_CONFIG_HOME/inspector/config`.

**Requirements:** SDL2, OpenGL. Attaching to a process requires appropriate permissions (e.g. ptrace, or run as the same user).

**Memory connectivity:** The inspector reads the target process’s memory in one of two ways. If the `raider_mem` kernel module is loaded, it uses `/dev/raider_mem` (kernel-side page-table read, no mmap_lock) for fast, low-overhead access. Otherwise it falls back to `process_vm_readv(2)`, which works with normal user permissions when the inspector runs as the same user as the target (or with ptrace capability). On attach, the UI reports which method is in use. No config is required; the choice is automatic.

---

**Adding inspector as MCP in Claude / Cursor (Copilot, etc.)**

The inspector speaks MCP over TCP (default port 8082). Clients expect a stdio subprocess, so we use `socat` to bridge stdio to the inspector’s port.

1. **Enable MCP in inspector**  
   Start the inspector, **Edit -> Settings**, check **Enable MCP server**, set **MCP port** to `8082`, **Save**. Leave the inspector running.

2. **Add the MCP server in your client**

   **Cursor** — Edit `~/.cursor/mcp.json` (or Cursor MCP settings UI) and add the inspector under `mcpServers`:

   ```json
   "raider-inspector": {
     "command": "socat",
     "args": ["STDIO", "TCP:127.0.0.1:8082,retry=30,interval=2"]
   }
   ```

   `retry=30,interval=2` makes socat retry the TCP connection so the client can connect after you start the inspector.

   **Claude Desktop** — Same idea in your Claude MCP config (e.g. `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or `%APPDATA%\Claude\` on Windows). Add a server that runs the same command:

   ```json
   "raider-inspector": {
     "command": "socat",
     "args": ["STDIO", "TCP:127.0.0.1:8082,retry=30,interval=2"]
   }
   ```

   Full Cursor example: `mcp.json` with only the inspector entry is `{"mcpServers":{"raider-inspector":{"command":"socat","args":["STDIO","TCP:127.0.0.1:8082,retry=30,interval=2"]}}}`. Use port `8082` unless you changed it in inspector Settings.
