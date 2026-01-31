# Case B: Network Outage (Standby Mode)

This scenario occurs when the endpoint loses internet connectivity, VPN drops, or the Wazuh Manager is down for maintenance.

## 🔍 Detection Logic
1.  **Identity:** Local keys exist.
2.  **Connectivity:** Connection to Wazuh API fails (Timeout, Connection Refused, or 5xx Error).

## 🛠️ Gozuh Action: STANDBY
* **Action:** Do Nothing (Skip Logic).
* **Behavior:** Gozuh logs the error and sleeps.
* **Reasoning:** * We cannot verify the server state.
    * We **must not** delete local keys, as this would cause data loss when the network returns.
    * The Wazuh Agent has an internal buffer; it will queue logs locally until the connection is restored.

```mermaid
graph TD
    Start([Start Watchdog]) --> Ping{🌐 API Reachable?}
    Ping -- No --> Log[📝 Log: Network Error]
    Log --> Standby[🛡️ Standby Mode]
    Standby --> Sleep[💤 Sleep]