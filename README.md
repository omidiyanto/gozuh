# GOZUH - Wazuh Agent Companion
![Gozuh Logo](docs/images/logo-head.png)
> **"Secure. Persistent. Automated."**

**Gozuh** is an enterprise-grade **Wazuh Agent Companion** built with Go. It serves as an intelligent wrapper and watchdog for the Wazuh Agent on Windows endpoints. It solves critical identity persistence challenges, automates disaster recovery, and ensures your security fleet remains healthy without manual intervention.

---

## 🌪️ The Problem

In dynamic IT environments, standard agents struggle with:

* **Duplicate Agents:** Re-imaging or re-installing often creates duplicate entries in the manager.
* **Identity Loss:** Disconnected agents cannot retrieve their old keys via standard API calls.
* **Ghost Assets:** Renaming a PC often leaves "zombie" records of the old name in the manager.
* **Cloned Disks:** Spinning up VMs from a "Golden Image" usually results in duplicate IDs or key conflicts.

## 🛡️ The Gozuh Solution

Gozuh acts as a "Guardian" for the agent identity. It does not trust the OS state blindly; instead, it trusts the **Hardware**.

### Key Features

* **🛡️ Hardware Identity Guard**
Gozuh generates a unique **Hardware Hash** derived from the motherboard UUID, BIOS Serial, and MAC Address. The agent name is locked to this signature: `hostname-[10_char_hash]`.
* **🧠 Hybrid Verification (The "Secret Sauce")**
When recovering an agent, Gozuh performs a strict verification:
1. **Active Agents:** Verifies identity via **Wazuh Config API**.
2. **Disconnected Agents:** Performs forensics on **Wazuh Indexer (OpenSearch)** logs to prove historical ownership.
*Result:* It restores the original encryption keys (`client.keys`) *only* if the hardware matches 100%.


* **🔄 Self-Healing & Watchdog**
A background service runs every 60 seconds to:
* **Revive:** Restart `WazuhSvc` if it crashes or is stopped by malware.
* **Enforce:** Re-inject the hardware hash into `ossec.conf` if tampered with.
* **Migrate:** Detect Hostname changes, delete the old agent record, and re-register automatically.


* **🧹 Instant Purge (Decommissioning)**
Decommission assets instantly using a specialized API call that bypasses Wazuh's standard 7-day deletion safeguard.

---

## ⚙️ How It Works (Workflow)

Gozuh uses a "Smart Suffix Search" algorithm (`O(1)` complexity) to find candidates, followed by a "Strict Hash Comparison".

```mermaid
graph TD
    Start([Start Gozuh]) --> Identity[Calculate Hardware Hash]
    Identity --> CheckLocal{Local State Valid?}
    
    %% Self Healing Path
    CheckLocal -- Yes --> ServiceCheck{Wazuh Service Running?}
    ServiceCheck -- No --> Restart[Restart Service]
    ServiceCheck -- Yes --> Idle([Sleep / Watchdog Mode])
    
    %% Installation / Recovery Path
    CheckLocal -- No --> Search[Search API for Suffix]
    Search --> Candidate{Candidate Found?}
    
    Candidate -- No --> Fresh[Fresh Install (New ID)]
    
    Candidate -- Yes --> Verify{Verify Full Hash}
    Verify -- Match (Via API) --> Restore[Restore Keys]
    Verify -- Match (Via Indexer Logs) --> Restore
    
    Verify -- Mismatch --> Conflict{Hostname Changed?}
    Conflict -- Yes --> Migrate[Delete Old Agent & Register New]
    Conflict -- No --> Fresh
    
    Restore --> SaveState[Update Local State]
    Fresh --> SaveState
    Migrate --> SaveState

```

---

## 🧪 Chaos Scenarios (Capabilities)

Gozuh is designed to survive infrastructure chaos. Here is how it handles specific scenarios:

| Scenario | Behavior | Outcome |
| --- | --- | --- |
| **Fresh Install** | New hardware detected. No existing suffix on server. | ✅ **Clean Registration.** New ID created. |
| **Disaster Recovery** | OS is wiped/re-installed. Agent was "Disconnected" on server. | ✅ **Identity Restored.** Gozuh queries Indexer logs, confirms hardware match, and recovers old keys. **No duplicate agent.** |
| **Hostname Change** | User renames PC from `DESKTOP-A` to `FINANCE-01`. | ✅ **Auto-Migration.** Gozuh detects name mismatch, deletes `DESKTOP-A` from server, and registers `FINANCE-01`. |
| **OS Disk Cloning** | Disk cloned from Machine A to Machine B. Hostname is same, but Hardware UUID changed. | ✅ **Conflict Prevention.** Gozuh detects Hash Mismatch. It treats Machine B as a NEW agent. Machine A's session remains safe. |
| **Tampering** | User deletes `client.keys` or stops the service. | ✅ **Self-Healing.** Service restarts automatically. Keys are recovered from the server if missing. |
| **Decommission** | Admin runs `--purge`. | ✅ **Total Cleanup.** Agent is removed from local PC *and* deleted permanently from Wazuh Manager instantly. |

---

## 📦 Installation & Usage

### Prerequisites

* Windows 10, 11, or Server.
* Network access to Wazuh Manager API (55000) and Indexer (9200).

### 1. Deployment Package

Your deployment folder should contain:

* `gozuh.exe` (The wrapper)
* `wazuh-agent-4.x.x.msi` (Original installer)
* `config.json` (Configuration)

### 2. Configuration (`config.json`)

```json
{
  "wazuh_url": "https://192.168.1.100:55000",
  "api_user": "wazuh-wui",
  "api_pass": "YourSecretPassword",
  "indexer_url": "https://192.168.1.100:9200",
  "indexer_user": "admin",
  "indexer_pass": "YourSecretPassword",
  "sync_interval": 60
}

```

### 3. Commands

#### 🟢 Smart Install (Idempotent)

Recommended for GPO / SCCM / Ansible. Safe to run repeatedly.

```powershell
.\gozuh.exe --install

```

#### 🟡 Local Uninstall

Removes the agent from the device but **keeps** the data on the server (status becomes *Disconnected*). Allows for future recovery.

```powershell
.\gozuh.exe --uninstall

```

#### 🔴 Purge (Decommission)

**Destructive.** Removes the agent locally AND deletes it permanently from the Wazuh Manager database.

```powershell
.\gozuh.exe --purge

```

#### 🔵 Debug / Pre-flight

Checks hardware identity and server connectivity without making changes.

```powershell
.\gozuh.exe --debug

```

---

## 🏗️ Building from Source

Requirements: Go 1.21+

1. Clone the repository.
2. Build the optimized binary:

```bash
go build -ldflags="-s -w" -o gozuh.exe ./cmd/gozuh/

```

---

## 📂 Project Structure

```text
GOZUH/
├── cmd/
│   └── gozuh/
│       └── main.go           # Entry point, CLI & Idempotency Logic
├── internal/
│   ├── config/               # Settings & State management
│   ├── identity/             # Hardware Fingerprinting (WMI/MAC)
│   ├── service/              # Background Watchdog Service
│   ├── sys/                  # Windows Service Control & MSI Exec
│   └── wazuh/                # API Client (Hybrid Verification Logic)
├── docs/
│   └── images/               # Assets
├── go.mod
└── config.json               # Template

```

---

**Developed for Enterprise DevSecOps.**
*Gozuh ensures your endpoint telemetry is as reliable as your infrastructure.*


