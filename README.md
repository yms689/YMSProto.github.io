# Virtual Environment: FortiGate Firewall, Wazuh Server, and T-Pot Honeypot for Creating IOCs

## Project Overview

This project sets up a virtualized network environment using Hyper-V, integrating a **FortiGate firewall**, **Wazuh SIEM**, and **T-Pot honeypots** for security monitoring. The main goal is to collect malicious IPs detected by the honeypot and generate **Indicators of Compromise (IOCs)** based on the data. These IOCs are then applied to the FortiGate firewall to block malicious traffic.

In addition to the on-premises setup, this environment can be deployed in the cloud using **Terraform**, ensuring the setup is preserved and easily reproducible. The cloud environment includes the Wazuh server running in Docker, where firewall rules are managed, and client VMs (e.g., a web server) configured with Wazuh agents to act as intrusion detection systems (IDS) and intrusion prevention systems (IPS).

## Objectives

- **Detect and Block Malicious IPs:** Set up a comprehensive monitoring system to identify and respond to threats.
- **Automate IOC Management:** Use scripts to extract and process threat data, automating the creation of blocking rules for the firewall.
- **Cloud Deployment:** Utilize Terraform to create a reproducible cloud environment for enhanced scalability and management.

## Lab Used to Test and Validate

1. **Deploy FortiGate Virtual Firewall**
   - Configure the FortiGate firewall for network security.

2. **Set Up Wazuh Server**
   - Install and configure the Wazuh server for security monitoring.

3. **Configure T-Pot Honeypot**
   - Deploy T-Pot honeypot in a cloud environment.
   - Ensure it collects attack data and logs malicious IPs in CSV format using KQL:
     ```sql
     event_type:alert AND src_ip:* AND ip_rep:* AND alert.category:*
     ```
 4. **Ldap server that monitor with Wazuh
    

## Extract and Process Honeypot Data**
   - Use Python or Bash scripts to read IPs from T-Pot's CSV log files and store them as Indicators of Compromise (IOC).

   **Python Script:**
   ```python
   import csv

   csv_file = "malicious-ip-detection.csv"
   output_file = "IPtoblock.txt"

   unique_ips = set()
   with open(csv_file, 'r') as file:
       reader = csv.DictReader(file)
       for row in reader:
           ip = row['src_ip']
           unique_ips.add(ip)

   with open(output_file, 'w') as file:
       for ip in sorted(unique_ips):
           file.write(f"{ip}\n")
Bash Script:

bash
Copy code
awk -F',' 'NR > 1 {print $2}' "malicious-ip-detection.csv" | sort | uniq > "IPtoblock.txt"
Upload Malicious IPs to Firewall

Use the IPtoblock.txt file stored in a Docker container (on the same server as the Wazuh SIEM) and upload it to the FortiGate firewall.
Store the IPtoblock.txt file in Azure Blob Storage for easy access by the Wazuh server.
Create Wazuh Rules for IOC Management

Create custom rules in local_rules.xml on the Wazuh server to match malicious IPs.
Sample Rule:

xml
Copy code
<group name="custom">
  <rule id="100200" level="10">
    <match>malicious_ip</match>
    <description>Detected malicious IP from T-Pot honeypot</description>
    <options>no_full_log</options>
    <action>exec</action>
    <command>/usr/bin/python3 /path/to/block_ip_script.py %IP%</command>
  </rule>
</group>
Set Up Wazuh Active Response

Configure Wazuh’s active response mechanism to automatically block malicious IPs in FortiGate using the extracted IOC data.
Monitor Using Wazuh Dashboard

Use the Wazuh dashboard to monitor detection and response to attacks.
Create custom visualizations to track:
Number of detected malicious IPs.
Active response actions (e.g., IP blocks).
Logs from T-Pot honeypots.
Conclusion
This project illustrates the effective integration of various security technologies to automate threat detection and response processes. The setup enhances the security posture of the environment by continuously monitoring for malicious activity and proactively blocking threats.

Prerequisites
Hyper-V: Ensure Hyper-V is installed and configured on your machine.
Terraform: Install Terraform for cloud deployment.
Docker: Install Docker to run the Wazuh server in a container.
FortiGate: Access to a FortiGate virtual firewall.
T-Pot: Knowledge of deploying T-Pot honeypots.
Future Work
Expand the network environment with additional client VMs for further testing and validation.
Enhance monitoring capabilities with additional tools and dashboards.
Improve the automation scripts for better performance and scalability.
