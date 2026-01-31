# Case G: Zombie Agent (Service Hung)

This scenario happens when the `WazuhSvc` is running locally, but the server sees the agent as "Disconnected" for an extended period (e.g., > 24 hours), possibly due to a stuck socket or buffer issue.

## 🔍 Detection Logic
1.  **Connectivity:** Healthy.
2.  **Local Status:** `WazuhSvc` is Running.
3.  **Server Status:** Agent status is `disconnected`.
4.  **Time Threshold:** `lastKeepAlive` > 24 Hours.

## 🛠️ Gozuh Action: RESTART SERVICE
* **Action:** Force Restart.
* **Steps:**
    1.  Log: `[DIAGNOSE] Case G: Zombie Agent`.
    2.  Stop `WazuhSvc`.
    3.  Wait 2 seconds.
    4.  Start `WazuhSvc`.
* **Outcome:** The agent reconnects to the manager and flushes its buffer.

```mermaid
graph TD
    Start([Start Watchdog]) --> CheckStatus{Status Disconnected?}
    CheckStatus -- Yes --> CheckTime{> 24 Hours?}
    CheckTime -- Yes --> Restart[♻️ Restart WazuhSvc]
    Restart --> Active([✅ Active])