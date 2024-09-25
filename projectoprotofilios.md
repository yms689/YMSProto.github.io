## **Portfolio: Detection and Prevention Lab Setup**

### **Project Overview**

The goal of this project was to design and implement a detection and prevention lab that combines multiple security technologies. The focus was on integrating **Wazuh SIEM** with Indicators of Attack (IOA) and Indicators of Compromise (IOC) data. This data is automatically collected from CSV files, which are stored on a **Docker-based IOC Server**. The CSV files are generated from **Nessus vulnerability scans** of the DMZ zone and from a **cloud-hosted honeypot**.

The key objective was to ensure that the system could regularly update the list of malicious IPs, enabling Wazuh to detect and respond to potential threats in real time.

---

### **Architecture and Setup**

The lab setup involved several interconnected components:

1. **Docker-based IOC Server**:
    - The IOC Server is a **Docker container** that stores and updates a list of malicious IPs (`malicious_ips.txt`) every day. 
    - CSV files containing IOA and IOC data are processed by a Python script that extracts unique IP addresses and updates the list. This list is then used by Wazuh to enhance its detection and response capabilities.
    - **Technologies Used**: Docker, Python, Pandas library

2. **Automated Python Script**:
    - A Python script (`update_ips.py`) was developed to scan a directory for new `.csv` files and extract any malicious IP addresses. 
    - The script ensures only `.csv` files are processed, and IP addresses are added to the `malicious_ips.txt` file without duplicates.

    Here’s a simplified version of the script:
    ```python
    import os
    import pandas as pd

    # Specify directory containing the CSV files
    csv_directory = '/app/csv_files'
    output_file = '/app/malicious_ips.txt'

    # Create a set to store unique IP addresses
    unique_ips = set()

    # Process each CSV file in the directory
    for filename in os.listdir(csv_directory):
        if filename.endswith('.csv'):
            csv_path = os.path.join(csv_directory, filename)
            try:
                # Read the CSV file and extract unique IPs from the 'src_ip' column
                df = pd.read_csv(csv_path)
                if 'src_ip' in df.columns:
                    ips = df['src_ip'].dropna().unique()
                    unique_ips.update(ips)
            except Exception as e:
                print(f"Error processing file {csv_path}: {e}")

    # Write the unique IPs to the output file
    with open(output_file, 'w') as file:
        for ip in sorted(unique_ips):
            file.write(f"{ip}\n")

    print("IP addresses updated successfully.")
    ```

3. **Docker Setup**:
    - The Docker container is configured to expose port 8080, allowing for access to the server that stores the malicious IP list. The CSV files are mounted as a volume inside the container so they can be processed by the Python script.
    
    Here’s the `Dockerfile` used:
    ```dockerfile
    FROM python:3.9-slim
    WORKDIR /app
    COPY IPtoblock.txt /app/malicious_ips.txt
    COPY update_ips.py /app/update_ips.py
    RUN pip install --no-cache-dir pandas
    EXPOSE 8080
    CMD ["python", "-m", "http.server", "8080"]
    ```

    - The container is run using the following command, which mounts the CSV files directory from the host:
    ```bash
    docker run -d -p 8080:8080 -v /path/to/csv_files:/app/csv_files ioc-server
    ```

4. **Nessus Vulnerability Scanning**:
    - A **Nessus vulnerability scanner** is deployed in a **DMZ zone** created using **FortiGate firewall** rules. The Nessus scans Active Directory and other systems, generating CSV reports with IOA and IOC data.
    - These reports are automatically sent to the Docker-based IOC server for processing.

5. **Wazuh Integration**:
    - **Wazuh SIEM** is set up to continuously monitor the `malicious_ips.txt` file. Whenever the file is updated, Wazuh loads the new IPs and uses them to generate alerts and block malicious traffic.
    - A custom rule was written to alert on any traffic from IPs in the `malicious_ips.txt` list. This allows for real-time detection of threats and immediate prevention.

    Example of a **Wazuh Rule**:
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

6. **Cloud-based Honeypot**:
    - A honeypot is deployed in the cloud to attract and capture malicious activity. The honeypot logs are stored in CSV files, which are also processed by the Docker-based IOC server.
    - **Technology Used**: T-Pot, hosted in AWS or Linode.

---

### **Security Enhancements**

- **DMZ Setup**:
    - A dedicated DMZ zone was created using FortiGate to isolate the Nessus scanner and honeypot from the internal network, while still allowing necessary traffic to flow between them.
    
- **IOA and IOC Automation**:
    - The Python script and Docker container automate the entire process of collecting IOA and IOC data from Nessus and the honeypot, ensuring the `malicious_ips.txt` file is always up to date.

- **Cron Job for Daily Updates**:
    - A cron job was set up to run the Python script daily, ensuring that any new CSV files are processed and the malicious IP list is updated regularly.

    Example cron job:
    ```bash
    0 2 * * * docker exec ioc-server python /app/update_ips.py
    ```

---

### **Results and Outcomes**

- **Automated Detection**: Wazuh is now automatically ingesting malicious IP data every day, enhancing its ability to detect and block attacks in real time.
- **Scalable Solution**: The Docker-based solution allows for easy scaling as additional data sources (e.g., more honeypots or vulnerability scanners) can be added with minimal configuration.
- **Enhanced Security Posture**: By combining Nessus, honeypots, Docker, and Wazuh, this setup ensures continuous monitoring, detection, and prevention of threats to the network.

---

### **Future Improvements**

- **More Honeypots**: Expanding the number of honeypots across different network segments to capture more detailed attack data.
- **Enhanced Reporting**: Creating a dashboard to track the number of malicious IPs blocked over time and visualizing trends in attacks.
- **Custom Alerts**: Refining Wazuh alerts to categorize threats based on severity for quicker response.

---

This approach provides a clear, hands-on demonstration of your expertise in automating threat detection and prevention using modern tools and techniques like Docker, Python scripting, Wazuh SIEM, and vulnerability scanners.
