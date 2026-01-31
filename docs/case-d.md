# Case D: Cloning Detected (Hardware Mismatch)

This is the most critical scenario. It occurs when a disk from **Computer A** is cloned or moved to **Computer B**. Computer B boots up thinking it is Computer A.

## 🔍 Detection Logic
1.  **Local State:** `client.keys` contains ID `011`.
2.  **Server State:** Server confirms ID `011` belongs to Hardware Hash `HASH_A`.
3.  **Physical State:** Gozuh calculates the current Hardware Hash as `HASH_B`.
4.  **Conflict:** `HASH_A` (Server) != `HASH_B` (Physical).

## 🛠️ Gozuh Action: MIGRATION (Source Safe)
* **Action:** Drop Invalid Identity (Safe Mode).
* **Reasoning:** We must **NOT** delete ID `011` from the server, because that ID belongs to the original Computer A (which might still be online). We only need to fix *this* computer.
* **Steps:**
    1.  Log: `[DIAGNOSE] Case D: Cloning Detected`.
    2.  Delete local `client.keys` (Drop the identity of Computer A).
    3.  Trigger `performRecovery()` using `HASH_B`.
    4.  If `HASH_B` is new, register as a new agent.
* **Outcome:** Computer A remains safe. Computer B gets a new, unique Agent ID.

```mermaid
graph TD
    Start([Start Watchdog]) --> Compare{Hash Match?}
    Compare -- No --> Log[📝 Log: Cloning Detected]
    Log --> Drop[🗑️ Drop Local Key]
    Drop --> Note[⚠️ DO NOT Delete Server Agent]
    Note --> NewReg[✨ Register as New Agent]