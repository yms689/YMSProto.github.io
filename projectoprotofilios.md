## **Portfolio: Detection and Prevention Lab Setup**

### **Project Goal**

The main objective of this project is to create a detection and prevention lab environment. In this setup:

1. **Wazuh SIEM** is configured to take Indicators of Attack (IOA) and Indicators of Compromise (IOC) from CSV files.
2. These CSV files are stored in a **Docker-based IOC Server**.
3. Data for the CSV files is generated from **Nessus scans in the DMZ zone** and from **honeypot sensors** deployed in the cloud.
4. The IOC Server updates daily, ensuring that Wazuh has a fresh list of malicious IPs for detection and blocking.

---

### **Architecture Overview**

- **Environment**:  
  - Wazuh SIEM is deployed and configured to handle IOC data.
  - Docker-based IOC Server is set up to collect and manage malicious IPs.
  - Nessus performs regular scans on the domain and generates CSV files with potential threats.
  - A honeypot in the cloud collects attack data from malicious actors.
  - Data is processed and integrated into Wazuh to enhance detection and prevention capabilities.

---

### **Components**

1. **Docker-based IOC Server**:
   - A Docker container that updates the `malicious_ips.txt` file every day by processing CSV files containing malicious IPs.
   - **Technologies**: Docker, Python, Pandas
   - **Automation**: The Python script (`update_ips.py`) processes new CSV files, extracts IP addresses, and stores them in a list that is automatically integrated into Wazuh.

2. **Python Automation Script (update_ips.py)**:
   - The script processes `.csv` files containing IOC and IOA data and adds unique IPs to a blacklist.
   - **Functionality**: The script only processes files with a `.csv` extension, extracting malicious IPs and ensuring no duplicates.
   
   ```python
   import os
   import pandas as pd

   # Directory where CSV files are stored
   csv_directory = '/app/csv_files'
   output_file = '/app/malicious_ips.txt'

   # Create a set to store unique IP addresses
   unique_ips = set()

   # Iterate through all CSV files in the specified directory
   for filename in os.listdir(csv_directory):
       if filename.endswith('.csv'):  # Only process files ending with .csv
           csv_path = os.path.join(csv_directory, filename)
           try:
               # Read the CSV file
               df = pd.read_csv(csv_path)
               # Extract IPs from the 'src_ip' column and add them to the set
               if 'src_ip' in df.columns:
                   ips = df['src_ip'].dropna().unique()  # Get unique IPs
                   unique_ips.update(ips)
           except Exception as e:
               print(f"Error processing file {csv_path}: {e}")

   # Write the unique IPs to the output file
   with open(output_file, 'w') as file:
       for ip in sorted(unique_ips):
           file.write(f"{ip}\n")

   print("IP addresses updated successfully.")
   ```

3. **Docker Configuration**:
   - The IOC server runs as a Docker container. CSV files containing IP data are mounted as a volume in the container, and the container is configured to process them every day via a cron job.
   
   **Dockerfile**:
   ```dockerfile
   FROM python:3.9-slim
   WORKDIR /app
   COPY IPtoblock.txt /app/malicious_ips.txt
   COPY update_ips.py /app/update_ips.py
   RUN pip install --no-cache-dir pandas
   EXPOSE 8080
   CMD ["python", "-m", "http.server", "8080"]
   ```
   
   **Cron Job for Daily Updates**:
   ```bash
   0 2 * * * docker exec ioc-server python /app/update_ips.py
   ```

4. **Nessus Vulnerability Scanning**:
   - **Scanning Setup**: A Nessus scanner is set up in a DMZ zone created in FortiGate to scan the Active Directory domain.
   - **Automation**: Nessus scans generate CSV reports of IOAs and IOCs, which are stored and processed by the Docker-based IOC server.

5. **Wazuh Integration**:
   - Wazuh is configured to read the `malicious_ips.txt` file updated by the Docker container.
   - Custom Wazuh rules are created to alert and block IPs from the file.
   
   **Wazuh Custom Rule Example**:
   ```xml
   <group name="malicious_ips">
       <rule id="100100" level="10">
           <decoded_as>json</decoded_as>
           <field name="src_ip">$(hostname)</field>
           <description>Malicious IP detected from Nessus scan or honeypot.</description>
           <mitre>
               <id>T1071</id>
           </mitre>
       </rule>
   </group>
   ```

6. **Cloud Honeypot**:
   - A honeypot deployed in the cloud collects attack data.
   - Collected data is converted into CSV format and passed to the IOC Server.
   - **Technology**: T-Pot, AWS or Linode for hosting.

7. **Apache Directory Studio for Active Directory Management**:
   - Used to join the domain, manage users, and perform administrative tasks related to Nessus scanning and threat detection.

---

### **Security Implementation:**

- **DMZ Setup**:
   - FortiGate firewall configured to isolate the Nessus scanner from the internal network, only allowing controlled traffic.
   - Nessus scans the domain via a Kali Linux machine in the DMZ.

- **IOA and IOC Management**:
   - Automatically updated IP lists ensure Wazuh SIEM has up-to-date information on malicious actors, improving its ability to detect and respond to threats.

---

### **Project Outcomes**

- **Daily Updates**: The malicious IP list is automatically updated from CSV files generated by Nessus scans and the honeypot.
- **Wazuh Monitoring**: Real-time detection and prevention of malicious IPs through Wazuh SIEM.
- **Scalability**: The architecture can be expanded to incorporate more data sources, such as additional honeypots or scanners.
- **Automation**: The entire workflow is automated to reduce manual intervention.

---

### **Next Steps**

- **Expand Data Sources**: Add more honeypots or scanners in other network zones.
- **Enhance Rule Logic**: Refine Wazuh rules to trigger different levels of alerts based on the severity of the threat.
- **Reporting**: Implement a dashboard for tracking the number of malicious IPs detected over time.

---

This structured portfolio highlights the technical aspects of your detection and prevention lab while showcasing the use of Docker, Python automation, Nessus scanning, cloud-based honeypots, and Wazuh integration. Let me know if you need more details on specific areas!
