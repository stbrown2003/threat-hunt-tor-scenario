# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.5.7.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9050, 9150, 9001, 9030, 9040).|

---

## Related Queries:
```kql
// Events involving the use of the tor browser
// employee installed tor and created a shopping list
let target_machine = "939st";
DeviceFileEvents
| where DeviceName == target_machine and FileName matches regex @"\btor\b" // excludes any files not tor related
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath

// silent installation of the tor browser via powershell
let target_machine = "939st";
DeviceProcessEvents
| where DeviceName == target_machine and AccountDomain != "nt authority"
| where ProcessCommandLine matches regex @"\btor-browser\b"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 

// proof of outbound connections over tor ports
let target_machine = "939st";
DeviceNetworkEvents
| where DeviceName == target_machine
| where ActionType == "ConnectionSuccess" // only filtering successfull connections
| where RemotePort in (9050, 9150, 9001, 9030, 9040) // commonly used TOR ports
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName

```

---

## Created By:
- **Author Name**: Steven Brown
- **Author Contact**: https://www.linkedin.com/in/stbrown2003/
- **Date**: September 23rd, 2025
