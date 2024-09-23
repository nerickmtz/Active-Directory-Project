# Active Directory Project

## Objective
The goal of this project was to set up a detection lab to simulate a realistic network environment that would be used to analyze and detect cyber attacks. Using the **Splunk** Security Information and Event Management (SIEM) system, logs were ingested from key components, and realistic attack scenarios were generated for testing. 

## Network Overview

Below is a diagram of the detection lab setup:
![1](https://github.com/user-attachments/assets/c6a2e1b2-0529-402d-b4c6-5c0468418223)

The network setup is configured as follows:

- **Domain**: Nerick
- **Network**: 192.168.10.0/24
- **Splunk Server**: 192.168.10.10
- **Active Directory (AD)**: 192.168.10.7
- **Attacker (Kali Linux)**: 192.168.10.250
- **Windows 10 Client**: DHCP enabled

Each system in this lab was set up for specific purposes:

### Splunk Server (192.168.10.10)
- **Role**: SIEM server for log ingestion and analysis.
- **Purpose**: The Splunk server collected logs from various sources, including Sysmon logs from the Windows 10 client and Active Directory, allowing for real-time monitoring of the lab environment.

### Active Directory (192.168.10.7)
- **Role**: Directory services for the lab environment.
- **Purpose**: Active Directory managed authentication and other services. It also had Sysmon and Splunk Universal Forwarder installed to send logs to the Splunk server.

### Attacker - Kali Linux (192.168.10.250)
- **Role**: Simulated attacker machine.
- **Purpose**: This system was used to execute various attack scenarios within the environment to test the detection capabilities of the SIEM setup.

### Windows 10 Client (DHCP IP)
- **Role**: Simulated end-user machine.
- **Purpose**: This machine was part of the network domain and had Sysmon and Splunk Universal Forwarder installed. It generated user and network activity logs for analysis in Splunk.

## Skills Learned

Throughout this project, I developed and honed several key skills:

- **Understanding of SIEM**: Gained proficiency in SIEM concepts and practical applications for log ingestion and analysis.
- **Log Analysis**: Acquired the ability to analyze and interpret various network and system logs for signs of suspicious or malicious activity.
- **Attack Pattern Recognition**: Learned to generate and recognize attack signatures, including common techniques used in cyber attacks.
- **Troubleshooting**: Gained hands-on experience diagnosing and resolving issues in a complex lab environment, from network misconfigurations to service errors.
- **Researching**: Improved my ability to research and find solutions for technical problems, using a variety of online resources and community forums.
- **Critical Thinking**: Enhanced my problem-solving skills in identifying and mitigating security threats within a network.

## Tools Used

The following tools and technologies were used to build and test the detection lab:

- **Splunk**: SIEM platform used for log ingestion and analysis.
- **Sysmon**: System Monitor to log detailed information on system activities.
- **Splunk Universal Forwarder**: To send logs from clients (Windows 10, AD) to the Splunk server.
- **Kali Linux**: For launching simulated attack scenarios.
- **Active Directory**: Provided directory services and user management for the lab environment.

## Virtual Machine Setup

To build this detection lab, all machines were created and managed using **Oracle VM VirtualBox**. Below is the list of virtual machines configured for the project:

![2](https://github.com/user-attachments/assets/8ce8c66e-7c32-4b20-8b48-0f63e39e15cf)

1. **Windows 10 (TARGET-PC)**:
   - Role: Target machine simulating user activity and logging through Sysmon, forwarding data to the Splunk Server.

2. **Kali Linux**:
   - Role: Penetration testing and attack simulation to generate logs for analysis.

3. **Active Directory (ADDC-01)**:
   - Role: Provides directory services, user authentication, and system monitoring through Sysmon. Logs are forwarded to the Splunk Server.

4. **Splunk Server**:
   - Role: Collects and analyzes logs from all networked systems, providing insights into security events.

Each virtual machine was configured to simulate a typical corporate network setup, allowing for the generation and analysis of network traffic and security incidents within the controlled lab environment.

## Setting Up Active Directory Domain Controller

As part of the detection lab setup, the Active Directory server was promoted to a domain controller to manage network authentication and other directory services.

Below is a screenshot of the process where the server was promoted to a Domain Controller:

![3](https://github.com/user-attachments/assets/665142cd-db73-41a6-94fc-232019d35679)

### Steps to Promote Server to Domain Controller:

1. **Install Active Directory Domain Services (AD DS)**:
   - Use the "Add Roles and Features" wizard in Windows Server Manager to install the AD DS role.
   - Once the role is installed, a notification appears prompting further configuration.

2. **Post-Deployment Configuration**:
   - In the **Post-deployment Configuration** notification, click on the link labeled **"Promote this server to a domain controller"** (as shown in the image above).
   - This will start the Active Directory Domain Services Configuration Wizard.

3. **Configure Active Directory**:
   - During the configuration, choose to create a new forest, specify the domain name, and configure other settings such as DNS and NetBIOS names.
   - The setup will configure and promote the server to a Domain Controller.

4. **Reboot and Finalize**:
   - After completing the configuration, the server will restart to apply changes. Once rebooted, it will function as the domain controller for the network.

This domain controller plays a crucial role in providing directory services and authentication for the Windows 10 client machine, ensuring that logs from these systems can be properly forwarded to the Splunk server for monitoring and analysis.

## Creating Users in Active Directory

As part of the setup for this detection lab, a user named **Brad Stevens** (username: `bstevens`) was created in Active Directory. This user account will be used to simulate normal user activity on the Windows 10 client machine, helping to generate logs for analysis in the Splunk server.

Below is a screenshot of the user creation process in Active Directory:

![4](https://github.com/user-attachments/assets/13610a8b-fcab-44b4-9c2f-190dab607405)

### Steps to Create a User in Active Directory:

1. **Open Active Directory Users and Computers**:
   - Go to **Server Manager** > **Tools** > **Active Directory Users and Computers**.

2. **Navigate to the Desired OU (Organizational Unit)**:
   - Expand the domain (`nerick.local` in this case) and select the **IT** Organizational Unit (OU) to store the user.

3. **Create a New User**:
   - Right-click on the OU where you want the user account to be created (e.g., **IT**).
   - Select **New** > **User**.
   - Enter the user’s first name (Brad), last name (Stevens), and user logon name (`bstevens`), as shown in the image above.

4. **Set User Account Options**:
   - Configure account options, such as:
     - Password policy (e.g., **User must change password at next logon** or **Password never expires**).
     - Account expiration settings (set to **Never** or define an expiration date).
   - In this example, the user account is set to never expire.

5. **Complete the User Creation**:
   - Finish the process by setting a password and confirming the account creation.
   - The user account is now active and ready to be used within the domain environment.

This user account will be used for various tasks such as logon events, file access, and other activities that are crucial for log monitoring and analysis within the Splunk SIEM environment.

## Joining Target-PC to the Active Directory Domain

In this step, the **Target-PC** (Windows 10 machine) is joined to the **NERICK.LOCAL** domain, enabling domain user accounts (such as `bstevens`) to access the system. This allows the machine to log activities and communicate with the domain controller for authentication purposes.

Below is a screenshot of the process for joining the machine to the domain:

![5](https://github.com/user-attachments/assets/0932aa8a-b164-4cea-8d4a-3de28e8cd708)

### Steps to Join a Machine to the Active Directory Domain:

1. **Open System Properties**:
   - Right-click on **This PC** and select **Properties**.
   - In the **About** section, click on **Advanced system settings** on the right.
   - In the **System Properties** window, click on the **Computer Name** tab, then click the **Change** button.

2. **Set Domain Membership**:
   - Under the **Computer Name/Domain Changes** window, ensure the computer name is set to `Target-PC`.
   - Select the **Domain** option and type the domain name: `NERICK.LOCAL` (as shown in the image above).
   - Click **OK** to proceed.

3. **Authenticate Domain Join**:
   - You will be prompted to enter the credentials of a domain user with permissions to join computers to the domain (such as an administrator account).
   - Enter the username and password and click **OK**.

4. **Confirmation**:
   - Once successfully authenticated, a welcome message will confirm that the computer has been added to the domain: **Welcome to the NERICK.LOCAL domain**.
   - Click **OK** and restart the computer to apply the changes.

5. **Log In with Domain Credentials**:
   - After the reboot, the machine is now part of the domain, and you can log in with domain user accounts such as `bstevens@nerick.local`.

Joining this Windows 10 client machine to the domain allows for central management, monitoring, and authentication services through the Active Directory, providing valuable logs to be ingested by the Splunk server for analysis.

## Installing Splunk on Ubuntu and Configuring Log Forwarding

In this step, we installed **Splunk Enterprise** on an Ubuntu server and configured **Windows 10 (Target-PC)** and **Windows Server (ADDC01)** to forward their logs to the Splunk server. This allowed the Splunk server to collect, index, and analyze logs from both hosts.

### Splunk Installation on Ubuntu

Below is a screenshot of the process where Splunk was installed on the Ubuntu server:

![6](https://github.com/user-attachments/assets/6ffe90a1-c055-40b2-9483-75d34ccb03d9)

## Verifying Log Forwarding from Hosts in Splunk

After configuring the **Universal Forwarder** on both the **ADDC01 (Windows Server)** and **Target-PC (Windows 10)** machines, logs from both hosts were successfully forwarded and indexed in Splunk. The logs can now be analyzed within the **Search & Reporting** app in Splunk.

Below is a screenshot from Splunk showing logs from both hosts:

![8](https://github.com/user-attachments/assets/69e69a6d-1a0f-4a64-9d83-ca468f338f88)

### Successful Log Forwarding:

- Both **ADDC01** and **Target-PC** hosts are visible in Splunk, as shown by the **host** field.
- A total of 2,624 logs from **ADDC01** and 2,504 logs from **Target-PC** were indexed, making up 100% of the total logs during the specified time range.
- These logs include **Windows Event Logs** from **Application**, **Security**, **System**, and **Sysmon**, which were forwarded via the Splunk Universal Forwarder.

### Configurations Used:

The following configurations were applied to ensure log forwarding:

1. **Splunk Universal Forwarder Configuration on Windows Hosts**:
   - Logs were forwarded using the **inputs.conf** configuration file, which defined the event logs to forward to the Splunk server.
   - Example configuration:

   ```plaintext
   [WinEventLog://Application]
   index = endpoint
   disabled = false

   [WinEventLog://Security]
   index = endpoint
   disabled = false

   [WinEventLog://System]
   index = endpoint
   disabled = false

   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   index = endpoint
   disabled = false
   renderXml = true
   source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

   ## Successful Log Forwarding Configuration

The log forwarding configuration was successfully implemented, as evidenced by the logs now visible in the Splunk **Search & Reporting** app. Below is a screenshot showing the different event sources being ingested from both **Target-PC** and **ADDC01**:

![11](https://github.com/user-attachments/assets/249546b2-f006-4413-8065-c0c81207a5d2)

### Event Sources

The screenshot shows that logs are being forwarded from the following Windows Event Log sources:

- **WinEventLog:Security**: 1,120 events (45.677%)
- **WinEventLog:Application**: 681 events (27.773%)
- **WinEventLog:System**: 364 events (14.845%)
- **XmlWinEventLog:Microsoft-Windows-Sysmon/Operational**: 287 events (11.705%)

These logs include security, application, system, and Sysmon logs, demonstrating that the configurations applied to the **Universal Forwarder** on both Windows machines are functioning as expected. 

### Breakdown of Events

- **Security Logs**: These contain detailed information regarding login attempts, resource access, and other security-related events.
- **Application Logs**: Provide details about application-level errors and information from the system.
- **System Logs**: Include information on system-level events such as hardware failures, driver errors, etc.
- **Sysmon Logs**: Detailed monitoring of system processes, network connections, and other events essential for threat detection.

### Conclusion

With the Splunk Universal Forwarder successfully configured and operational, logs from **Target-PC** and **ADDC01** are being collected and indexed in Splunk, allowing for comprehensive monitoring and analysis of events within the lab environment.

## Attack Simulation: Brute Force RDP using Kali Linux and Crowbar

After configuring all the machines in the lab, I used **Kali Linux** to simulate a brute force attack on the **Target-PC** (Windows 10) using the **crowbar** tool and a subset of passwords from the **rockyou.txt** wordlist. The goal was to demonstrate how easily weak passwords can be exploited in a remote desktop environment.

### Brute Force Attack Details

1. **Password List Creation**:
   - I extracted the top 20 passwords from the **rockyou.txt** wordlist that is included with Kali Linux and saved them into a custom password list file named `passwords.txt`. Below is a screenshot showing the contents of the `passwords.txt` file:

   ![13](https://github.com/user-attachments/assets/23484823-8217-4338-838c-bfa6069b80d5)

2. **Crowbar Attack**:
   - Using **crowbar**, I attempted to brute force the RDP login for **bstevens**, a user created in the Active Directory domain. The password for **bstevens** was set as `P@$$w0rd!`.
   - The attack was successful, as **crowbar** managed to find the correct password after testing a few combinations from the `passwords.txt` file.
   
   Below is a screenshot of the crowbar command and output showing the successful login attempt:

   ![14](https://github.com/user-attachments/assets/52a36e48-b2b2-45ff-939f-002a0b67deaf)

## Detecting Brute Force Attack Using Splunk

After executing the brute force attack using **crowbar** from Kali Linux, I utilized **Splunk** to detect the attack based on failed login attempts. The **Windows Event ID 4625** (Login Failed) was used to identify unsuccessful authentication attempts for the **bstevens** account on **Target-PC**.

Below is the screenshot of the result 

![15](https://github.com/user-attachments/assets/060728d4-3d72-4d75-92a6-495b3f999e22)

Key Findings
A total of 22 failed login attempts (Event ID 4625) were recorded for the bstevens account.

These events occurred almost simultaneously, indicating a brute force attack, where multiple login attempts with incorrect credentials were made in rapid succession.

The EventCode 4625 represents failed login attempts. Below is a detailed view of the event count:

EventCode: 4625 (Login failed)
Count: 22 failed login attempts
Account: bstevens
Screenshot of the Search Results
The screenshot above shows the Event ID 4625 results in Splunk, with a total of 22 failed login attempts for the bstevens account

Event ID 4625: Represents a failed login attempt in Windows security logs.
Account Name: bstevens — The user account targeted by the brute force attack.
Host: The attack was attempted on the Target-PC.
The spike in failed login events is characteristic of a brute force attack, where an attacker tries different password combinations to gain unauthorized access.

By analyzing Event ID 4625 in Splunk, I was able to successfully detect a brute force attack targeting the bstevens account. This demonstrates the effectiveness of log monitoring for detecting malicious activities. Setting up alerts for patterns like multiple failed logins in a short timeframe can significantly enhance the security monitoring capabilities of a system.

## Detecting Successful Brute Force Attack Using Splunk

After monitoring the failed login attempts with **Event ID 4625**, I also detected a successful login event that resulted from the brute force attack. This event is represented by **Event ID 4624** (Successful Logon), which indicates a successful login to the **Target-PC** using the **bstevens** account from the Kali Linux machine.

![16](https://github.com/user-attachments/assets/76d1a047-3a38-46de-a3a9-34454a84f52b)

Key Findings
Event ID 4624: Indicates a successful login attempt.
Source IP: The source of the login came from the Kali Linux machine with the IP address 192.168.10.250.
Account Name: The login was for the user bstevens on the Target-PC.
EventCode: 4624 (Logon Success)
Keywords: Audit Success — This shows that the authentication was successful, confirming that the brute force attack succeeded.
Screenshot of the Search Results
The screenshot below shows the Event ID 4624 results in Splunk, confirming that the bstevens account was successfully accessed from the Kali Linux machine:

Event ID 4624: Represents a successful login in Windows security logs.
Account Name: bstevens — The account that was targeted and successfully compromised in the brute force attack.
Source IP Address: 192.168.10.250, which corresponds to the Kali Linux machine used in the brute force attack.
The successful login following the failed attempts confirms the brute force attack’s success.

By analyzing Event ID 4624 in Splunk, I was able to confirm that the brute force attack against the bstevens account was successful. The login attempt originated from the Kali Linux machine, demonstrating the effectiveness of monitoring logon success and failure events to detect potential security breaches.

## Conclusion

Through this project, I gained hands-on experience in building and configuring a fully functional detection lab, simulating real-world cyber attack scenarios, and detecting them using Splunk. Below are some key takeaways:

1. **SIEM Implementation**: 
   - I learned how to set up a **Splunk** server and configure **Universal Forwarders** to collect logs from different systems. This gave me a deeper understanding of log collection, indexing, and searching through Splunk.

2. **Log Analysis and Monitoring**:
   - I developed the skills to monitor and analyze logs, including **Windows Event Logs** such as **Event ID 4625** (Failed Logins) and **Event ID 4624** (Successful Logins). This helped me understand the importance of monitoring critical security events for detecting malicious activities like brute force attacks.

3. **Attack Simulation**:
   - By simulating a **brute force attack** using **Kali Linux** and tools like **crowbar**, I gained insight into how attackers exploit weak passwords to gain unauthorized access. This practical simulation helped solidify my understanding of common attack techniques and how to detect them using security monitoring tools.

4. **Security Best Practices**:
   - I reinforced my knowledge of the importance of enforcing **strong password policies**, **account lockout mechanisms**, and **multi-factor authentication (MFA)** to mitigate the risks posed by brute force attacks and other credential-based attacks.

5. **Troubleshooting and Research**:
   - Throughout the project, I enhanced my troubleshooting and researching skills by identifying and resolving configuration issues, researching different solutions for log forwarding, and optimizing the detection environment.

### Overall Takeaway

This project allowed me to build a comprehensive understanding of both the offensive and defensive sides of cybersecurity. From setting up a simulated attack environment to successfully detecting and analyzing security events in Splunk, I now have a clearer view of how crucial log monitoring and incident response are in real-world cybersecurity operations. The ability to detect and respond to threats efficiently is key to maintaining a secure network environment, and this project gave me valuable experience in achieving that goal.

