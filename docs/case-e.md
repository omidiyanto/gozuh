# Case E: Hostname Change

This scenario occurs when a user or admin renames the computer (e.g., from `DESKTOP-123` to `FINANCE-01`).

## 🔍 Detection Logic
1.  **Hash Match:** Server Hash == Physical Hash (It is the same machine).
2.  **Name Mismatch:** Local Hostname (`FINANCE-01`) != Server Agent Name (`DESKTOP-123`).

## 🛠️ Gozuh Action: RENAME
* **Action:** Update Identity.
* **Steps:**
    1.  Log: `[DIAGNOSE] Case E: Hostname Changed`.
    2.  **Delete Agent on Server:** Since the hash matches, we know this is the *same* machine. We remove the old record to prevent duplicates.
    3.  Delete local `client.keys`.
    4.  Register as `FINANCE-01`.
* **Outcome:** The old name disappears, and the agent reappears immediately with the new name.

```mermaid
graph TD
    Start([Start Watchdog]) --> CheckName{Name Match?}
    CheckName -- No --> DeleteRemote[🗑️ Delete Old Agent on Server]
    DeleteRemote --> DeleteLocal[🗑️ Delete Local Key]
    DeleteLocal --> Register[✨ Register New Name]