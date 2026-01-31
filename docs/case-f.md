# Case F: Local Corruption (Recovery)

This scenario occurs if `client.keys`, `state.json`, or `ossec.conf` are deleted or tampered with (by a user, malware, or disk error).

## 🔍 Detection Logic
* **Sub-Case 1 (Missing Key):** Hardware matches, but `client.keys` is missing.
* **Sub-Case 2 (Config Tampering):** `state.json` or `ossec.conf` contains a "Fake" hash that doesn't match the physical hardware.

## 🛠️ Gozuh Action: RECOVERY / FIX CONFIG
* **Action:** Restore from Server or Self-Repair.
* **Steps:**
    1.  **If Config is wrong:** Overwrite `state.json` and `ossec.conf` with the real Hardware Hash. Restart Service.
    2.  **If Key is missing:**
        * Search Wazuh API for an agent with the current Hardware Hash.
        * **If Found:** Download the key and restore it.
        * **If Not Found:** Trigger fresh registration.
* **Outcome:** The agent is restored to a healthy state without creating duplicate records.

```mermaid
graph TD
    Start([Start Watchdog]) --> CheckIntegrity{Config/Keys OK?}
    CheckIntegrity -- No --> Fix[🔧 Fix Config Files]
    Fix --> Search[🔎 Search Owner on Server]
    Search -- Found --> Restore[📥 Restore Key]
    Search -- Not Found --> Register[✨ Fresh Register]