<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/stbrown2003/threat-hunt-tor-scenario/blob/main/scenario-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "939st" a file-created event for tor.exe at `C:\Users\939st\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe` and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-09-23 7:53:08 PM`. 

**Query used to locate events:**

```kql
// Events involving the use of the tor browser
// employee installed tor and created a shopping list
let target_machine = "939st";
DeviceFileEvents
| where DeviceName == target_machine and FileName matches regex @"\btor\b" // excludes any files not tor related
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```
<img width="1186" height="360" alt="image" src="https://github.com/user-attachments/assets/f1c10373-28f8-4df9-a803-57b7f53bd34a" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string `tor-browser-windows-x86_64-portable-14.5.7.exe`. Based on the logs returned, at Sep 22, 2025 11:50:01 PM, an employee on the "939st" device ran the file `tor-browser-windows-x86_64-portable-14.5.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
// silent installation of the tor browser via powershell
let target_machine = "939st";
DeviceProcessEvents
| where DeviceName == target_machine and AccountDomain != "nt authority"
| where ProcessCommandLine matches regex @"\btor-browser\b"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1165" height="195" alt="image" src="https://github.com/user-attachments/assets/368f31a2-af8e-481e-a200-2a97801bc288" />

---

### 3. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for outbound connections from the machine to known TOR ports. At Sep 22, 2025 11:51:39 PM, an employee on the "939st" device successfully established a connection to the remote IP address `185.162.249.126` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `C:\Users\939st\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`. There were a couple of other connections to sites over port `9150` by the process `firefox.exe`.

**Query used to locate events:**

```kql
// proof of outbound connections over tor ports
let target_machine = "939st";
DeviceNetworkEvents
| where DeviceName == target_machine
| where ActionType == "ConnectionSuccess" // only filtering successfull connections
| where RemotePort in (9050, 9150, 9001, 9030, 9040) // commonly used TOR ports
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="1179" height="343" alt="image" src="https://github.com/user-attachments/assets/d69eb685-f60e-4a6e-976d-e73d20d2e3d4" />

---

## Chronological Event Timeline 

### 1. Tor Browser Installation

- 11:50:01 PM: On device 939st, `tor-browser-windows-x86_64-portable-14.5.7.exe` was executed from C:\Users\939st\Downloads\... using a silent install (/S). Process created via `cmd.exe`, initiated by `explorer.exe`.
- 11:50:23 PM: File `tor.exe` created at `C:\Users\939st\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe` (Tor core executable).


### 2. Network Connection - TOR Network

- 11:51:39 PM: tor.exe connected successfully to remote IP `185.162.249.126` on port `9001` (Tor relay port).
- 11:51:41 PM: tor.exe connected to remote IPs `65.21.94.13` and `185.162.249.126` on port `9001`.
- 11:52:39 PM: firefox.exe connected to `127.0.0.1:9150` (Tor SOCKS proxy localhost connection).

### 3. Additional Network Connections - TOR Browser Activity

- 7:45:40 PM: firefox.exe connected again to `127.0.0.1:9150` (Tor browsing session initiated).

### 4. File Creation - TOR Shopping List

- 7:53:08 PM: A Windows shortcut `tor-shopping-list.lnk` was created in `C:\Users\939st\AppData\Roaming\Microsoft\Windows\Recent\`, suggesting the user accessed/opened a file or application named `tor-shopping-list` through Tor.

---

## Summary

- On the evening of September 22, 2025, the Tor Browser was installed on device 939st. This installation was done in a way that didn’t require user interaction (a “silent” install). Soon after, the program began connecting to the Tor network, which is commonly used to browse the internet anonymously.
- The browser was successfully set up and started routing traffic through Tor. The following day, September 23, 2025, the browser was used again. During this activity, a shortcut called `tor-shopping-list` was created on the computer, showing that the user opened or interacted with a file or link while using Tor.

---

## Response Taken

TOR usage was confirmed on the endpoint `939st`. The device was isolated, and the user's direct manager was notified.

---
