# AbuseIPDB Script

This repository contains a Python script that integrates with the AbuseIPDB API to query reputation information for IP addresses. AbuseIPDB is a community-driven IP abuse reporting database that helps analysts and defenders enrich investigative data with threat context.

The script is designed for security practitioners to automate IP reputation lookups and streamline threat intelligence enrichment during investigations or incident response.

---

## 🚀 What This Script Does

- Connects to the **AbuseIPDB API** using your API key  
- Accepts one or more IP addresses as input  
- Retrieves reputation data (threat score, reports, last reported, categories)  
- Outputs results in a human-friendly format  
- Supports both single and batch IP queries

This tool aids in threat hunting, SOC investigations, and rapid enrichment of suspicious IP addresses encountered in logs or alerts.

---

## 🧠 Why This Matters

IP reputation is a common and powerful signal in security investigations:

- Helps analysts decide priority for incident triage  
- Complements other telemetry like alerts and host behavior  
- Automates what would otherwise be manual lookups  
- Can be incorporated into detection pipelines or SOAR playbooks

This script makes it easy to add reliable IP threat context to your workflows without manual lookups.

---

## ⚙️ Prerequisites

Before running the script, make sure you have:

- Python 3.6+ installed  
- An **AbuseIPDB API key** (free accounts are available for low-volume use)

---

## 📦 Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ASHDEX/AbuseIPDB-script.git
