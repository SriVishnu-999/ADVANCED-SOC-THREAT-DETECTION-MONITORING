# 🛡️ Advanced SOC Threat Detection & Monitoring

> A hands-on Security Operations Center (SOC) project built from scratch using **Splunk Enterprise 10.2.0** on a Windows machine — detecting real-world attack patterns through Windows Security Event Log analysis.

---

## 📌 Project Overview

This project demonstrates a fully functional SIEM-based threat detection pipeline covering **5 real-world attack scenarios** — from suspicious PowerShell execution to insider threat detection. Every detection rule, SPL query, and alert was personally designed and tested on a live Windows environment.

Built as a portfolio project to showcase practical SOC skills as a **fresher entering the cybersecurity field**.

---

## 🖥️ Environment

| Component | Details |
|-----------|---------|
| **SIEM Platform** | Splunk Enterprise 10.2.0 |
| **OS** | Windows 10 (DESKTOP-JLDKHC7) |
| **Log Source** | `WinEventLog:Security` |
| **Shell** | Windows PowerShell |
| **Detection Language** | SPL (Search Processing Language) |

---

## 🎯 Threat Scenarios Detected

### 1. 🔵 Suspicious PowerShell Execution — `EventCode 4688`

Simulated a fileless malware launch using PowerShell with evasion flags.

```powershell
powershell -nop -w hidden
```

**Splunk Query:**
```spl
EventCode=4688
```

**Result:** 11 process creation events detected in real time.

**MITRE ATT&CK:** `T1059.001` — Command and Scripting Interpreter: PowerShell

---

### 2. 🔴 Brute-Force / Multiple Failed Logins — `EventCode 4625`

Detected repeated authentication failures grouped by account and source IP, filtered above a threshold.

**Splunk Query:**
```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
```

**Result:** 2 accounts flagged (`DESKTOP-JLDKHC7$` and `Vishnu`) — each with 6 failures from `127.0.0.1`.

**Alert Created:** `Multiple Failed Logins` — Scheduled, triggers when count > 0.

**MITRE ATT&CK:** `T1110` — Brute Force

---

### 3. 🟡 Successful Logon Baseline — `EventCode 4624`

Established a normal logon baseline to support correlation with failed logon events.

**Splunk Query:**
```spl
EventCode=4624
```

**Result:** 455 successful logon events across 15 accounts.

**MITRE ATT&CK:** `T1078` — Valid Accounts

---

### 4. 🔴 Success After Failure — Compromised Account — `EventCode 4625 + 4624`

Correlated failed logons followed by a successful login within 10 minutes — the classic pattern of a successful brute-force attack.

**Splunk Query:**
```spl
index=* (EventCode=4625 OR EventCode=4624)
| transaction Account_Name maxspan=10m
| search EventCode=4624
```

**Result:** 458 correlated events — failure-then-success pattern confirmed across accounts.

**Alert Created:** `Success After Failure (Compromised Account)` — Per-Result trigger, **Medium** severity.

**MITRE ATT&CK:** `T1078` — Valid Accounts (post-compromise)

---

### 5. 🔴 Privilege Escalation — `EventCode 4672`

Detected special privilege assignments at logon (e.g. `SeDebugPrivilege`, `SeTcbPrivilege`) — a strong indicator of privilege escalation attempts.

**Splunk Query:**
```spl
index=* EventCode=4672
```

**Result:** 426 events across 8 domain accounts.

**Alert Created:** `Privilege Escalation` — Per-Result trigger, **HIGH** severity.

**MITRE ATT&CK:** `T1548` — Abuse Elevation Control Mechanism

---

### 6. 🟡 Insider Threat — Unauthorized Account Creation — `EventCode 4720`

Detected a new user account created outside normal working hours — flagged as a potential insider threat or attacker persistence mechanism.

**Splunk Query:**
```spl
index=* EventCode=4720
```

**Result:** 1 account creation event at `4:09:45 PM` — flagged as anomalous.

**Alert Created:** `Account Created` — Per-Result trigger, **Medium** severity, description: *Insider Threat*.

**MITRE ATT&CK:** `T1136` — Create Account

---

## 📊 Alerts Summary

| Alert Name | EventCode(s) | Severity | Trigger Condition | Type |
|---|---|---|---|---|
| Multiple Failed Logins | 4625 | 🟡 Medium | count > 5 per account | Scheduled |
| Success After Failure | 4625 + 4624 | 🟡 Medium | Failure then success in 10m | Scheduled |
| Privilege Escalation | 4672 | 🔴 High | Any special privilege logon | Scheduled |
| Account Created | 4720 | 🟡 Medium | Any new account creation | Real-time |
| Suspicious PowerShell | 4688 | 🔴 High | Hidden PowerShell process | Real-time |

---

## 🗺️ MITRE ATT&CK Coverage

```
Execution            →  T1059.001  (PowerShell)
Credential Access    →  T1110      (Brute Force)
Initial Access       →  T1078      (Valid Accounts)
Privilege Escalation →  T1548      (Abuse Elevation Control)
Persistence          →  T1136      (Create Account)
```

---

## 🛠️ Skills Demonstrated

- **Splunk Enterprise** — Search, statistics, transaction correlation, alerting
- **SPL (Search Processing Language)** — Custom detection queries with `stats`, `where`, `transaction`
- **Windows Security Event Log Analysis** — Deep understanding of EventCodes 4624, 4625, 4672, 4688, 4720
- **Detection Engineering** — Threshold-based, correlation-based, and per-result alerting
- **MITRE ATT&CK Framework** — Mapping detections to real adversary techniques
- **Threat Hunting** — Hypothesis-driven log investigation
- **Incident Documentation** — Clear, structured reporting of findings

---

## 📁 Project Structure

```
📦 soc-threat-detection-splunk
 ┣ 📂 screenshots/
 ┃ ┣ 01_powershell_execution.png
 ┃ ┣ 02_eventcode_4688_splunk.png
 ┃ ┣ 03_failed_logins_4625.png
 ┃ ┣ 04_successful_logons_4624.png
 ┃ ┣ 05_process_creation_alltime.png
 ┃ ┣ 06_brute_force_stats.png
 ┃ ┣ 07_alert_multiple_failed_logins.png
 ┃ ┣ 08_alert_success_after_failure.png
 ┃ ┣ 09_alert_privilege_escalation.png
 ┃ ┗ 10_alert_account_created.png
 ┣ 📂 queries/
 ┃ ┣ brute_force_detection.spl
 ┃ ┣ compromised_account_correlation.spl
 ┃ ┣ privilege_escalation.spl
 ┃ ┗ account_creation_insider_threat.spl
 ┣ 📄 SOC_Project_Report.docx
 ┗ 📄 README.md
```

---

## 🚀 How to Reproduce

1. Install **Splunk Enterprise** (free trial at [splunk.com](https://www.splunk.com))
2. Configure a Windows **Data Input** → `WinEventLog:Security`
3. Copy the SPL queries from the `queries/` folder into the Splunk search bar
4. Use **Save As → Alert** on each query to replicate the alert setup
5. Trigger test events on your Windows machine (failed logins, process creation, etc.)

---

## 👤 About

**Vishnu**
Fresher | Aspiring SOC Analyst
Passionate about threat detection, log analysis, and building practical cybersecurity skills through hands-on projects.

---

## 📄 License

This project is for educational and portfolio purposes only.
