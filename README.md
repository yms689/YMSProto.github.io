Virtual Environment: FortiGate Firewall, Wazuh Server, and T-Pot Honeypot for Creating IOCs
This project sets up a virtualized network environment using Hyper-V. It integrates a FortiGate firewall, Wazuh SIEM, and T-Pot honeypots for security monitoring. The goal is to collect malicious IPs detected by the honeypot and generate Indicators based on the data. These IOCs are then applied to the FortiGate firewall to block them.
And create this enviorment in cloud, meaning presaeve the setup and create it with teraform,
in the cloud the enviorment will hace the Wazuh server with the docker, take out the firewall ruls and build them in the cloud, creat client vm's in diffrent subnet(2 or just one web server) that have wazug agent and act as IPS/IDS to this web server.

Project Overview
This project demonstrates how to create IOC and ruled that detect them and block them and thought process to mitigate a response once activity detected.

Lab that used to test and validate:
1. Deploy FortiGate Virtual Firewall
2. Set Up Wazuh Server
3. Configure T-Pot Honeypot
Deploy T-Pot honeypot on a cloud environment.
Ensure it is collecting attack data and logging malicious IPs in CSV format (e.g., malicious-ip-detection.csv) with KQL 
event_type :alert AND src_ip:* AND ip_rep :* AND alert.category:*
saved to CSV
4. Extract and Process Honeypot Data
Use Python or Bash scripts to read the IPs from T-Pot's CSV log files and store them as Indicators of Compromise (IOC):
Python Script:
python
Copy code
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
5. Upload Malicious IPs to Firewall using txt file that stored in docker container( used container in the same server the store the Wazhu SIEM)
Store the IPtoblock.txt file in Azure Blob Storage for easy access by the Wazuh server.
6. Create Wazuh Rules for IOC Management
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
7. Set Up Wazuh Active Response
Configure Wazuh’s active response mechanism to automatically block malicious IPs in FortiGate by using the extracted IOC data.
8. Monitor Using Wazuh Dashboard
Use the Wazuh dashboard to monitor the detection and response to attacks. You can create custom visualizations to track the following:
Number of detected malicious IPs.
Active response actions (e.g., IP blocks).
Logs from T-Pot honeypots.




