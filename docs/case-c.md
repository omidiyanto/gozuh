# Case C: Ghost Agent (Server-Side Deletion)

This scenario happens when an Administrator accidentally deletes an agent from the Wazuh Manager, but the endpoint is still running.

## 🔍 Detection Logic
1.  **Connectivity:** API Server is reachable.
2.  **Local State:** `client.keys` exists locally.
3.  **Server State:** API returns **404 Not Found** for the local Agent ID.

## 🛠️ Gozuh Action: SELF-HEAL
* **Action:** Drop Key & Re-register.
* **Steps:**
    1.  Log: `[DIAGNOSE] Case C: Ghost Agent`.
    2.  Delete local `client.keys`.
    3.  Trigger `performRecovery()` to register as a new agent.
* **Outcome:** The agent reappears in the dashboard (potentially with a new ID).

```mermaid
graph TD
    Start([Start Watchdog]) --> CheckServer{☁️ Agent Exists?}
    CheckServer -- No (404) --> Delete[🗑️ Delete Local Key]
    Delete --> Register[✨ Fresh Register]
    Register --> Active([✅ Active])