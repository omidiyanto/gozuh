# Case A: Normal Operation (Fully Synced)

This is the ideal state of the agent. Gozuh verifies that the local environment matches the server environment perfectly.

## 🔍 Detection Logic
1.  **Connectivity:** API Server is reachable.
2.  **Identity:** Local `client.keys` exists and matches the Server Agent ID.
3.  **Integrity:** Hardware Hash in `state.json` matches the physical hardware.
4.  **Verification:** The Hardware Hash stored on the Server matches the physical hardware.
5.  **Status:** The Server reports the agent status as `Active`.

## 🛠️ Gozuh Action: IDLE
* **Action:** None.
* **Behavior:** Gozuh enters a sleep state for `sync_interval` (default 60s).
* **Reasoning:** The system is healthy. Unnecessary restarts or API calls are avoided to save resources.

```mermaid
graph TD
    Start([Start Watchdog]) --> Check{Everything Matches?}
    Check -- Yes --> Sleep[💤 Sleep 60s]
    Sleep --> Start