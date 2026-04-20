# Azure SOC / Honeypot Lab: Global Threat Visualization

## 🛡️ Introduction
This project involved the deployment of a **Cloud-Native SOC (Security Operations Center)** using **Microsoft Sentinel** and a **Windows Virtual Machine** acting as a honeypot. The primary goal was to expose the VM to the public internet, ingest security logs into a Log Analytics Workspace, and visualize global brute-force attacks in real-time using **Kusto Query Language (KQL)** and Azure Workbooks.

## 🏗️ Technologies & Tools Used
* **Azure Virtual Machine:** Windows-based "victim" system.
* **Microsoft Sentinel:** Cloud-native SIEM (Security Information and Event Management).
* **Log Analytics Workspace:** The centralized log repository.
* **Kusto Query Language (KQL):** Used for log parsing and data transformation.
* **Azure Workbooks:** Data visualization and mapping.
* **Watchlists:** Used to map IP addresses to geographical data via a custom GeoIP database.

---

## 🛠️ Implementation Steps

### 1. Infrastructure Deployment
* Provisioned a Windows VM within a dedicated Azure Resource Group.
* Configured **Network Security Groups (NSG)** to allow inbound traffic from any source to simulate a vulnerable endpoint.
* Disabled the Windows Firewall on the guest OS to ensure all connection attempts were logged at the network and application layer.

### 2. Log Ingestion Pipeline
* Connected the VM to a **Log Analytics Workspace**.
* Configured **Microsoft Sentinel** with the **Windows Security Events via AMA** connector.
* Verified that **Event ID 4625 (Failed Login)** was being successfully ingested.

### 3. Threat Intelligence & Mapping
* Uploaded a custom **GeoIP Watchlist** containing global IP ranges, latitudes, longitudes, and country codes.
* Utilized the `ipv4_lookup` operator in KQL to perform a join between raw security logs and the GeoIP data.

---

## 🔍 Data Analysis (KQL)
The following query was developed to correlate attacker IP addresses with their physical locations:

```kusto
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname, 
  friendly_location = strcat(cityname, " (", countryname, ")")
```

---

## 📊 Visualizations

### Global Attacker Heatmap
> **[INSERT SCREENSHOT OF YOUR MAP HERE]*
*This map visualizes the geographical origin of thousands of brute-force attempts within 24 hours of system exposure.*

### Log Analytics Verification
> **[INSERT SCREENSHOT OF YOUR DATA SOURCE / LOGS HERE]**
*Verification that Event ID 4625 logs are successfully flowing into the workspace.*

---

## 📈 Key Findings
* **Automation:** Within minutes of exposure, the system was identified and targeted by automated bots.
* **High-Volume Origins:** Significant attack volume originated from regions known for hosting botnets and scanning infrastructure.
* **Detection Efficacy:** Using Sentinel, I was able to transform raw, noisy log data into actionable intelligence, identifying specific threat actors by their IP reputation and frequency of attack.

## 🧹 Post-Project Cleanup
To maintain cost-efficiency, all Azure resources (VM, Disk, Public IP, and Workspace) were deleted immediately following the data collection phase to prevent unnecessary cloud consumption.
