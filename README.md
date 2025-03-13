<H1 align="center">Redline-Stealer Traffic Investigation</H1>

<H2>PCAP Analysis report</H2>
<p align="left">
<b>Report Title</b>: Redline-Stealer Traffic Investigation <br>
<b>Analyst</b>: Exia <br>
<b>PCAP File Name<b/: 2024-10-23-Redline-Stealer-infection-traffic.pcap <br>
<b>File Size</b>: 6.2 MB <br>
<b>Date of Capture</b>: 2024-10-23 <br>
</p>

<h2>1. Executive Summary:</h2>
<p>
  A malware infection (RedLine Stealer) was detected on an internal system (10.0.23.101). The malware attempted to<br> steal credentials, cryptocurrency wallet files, and other sensitive data by communicating with a known Command-and-Control (C2) server
</p>
<br>
<h2>Indicators of Compromise (IoCs):</h2>
<p>
    1. Malicious IP Address: 188.190.10.10 (External C2 server <br>
</p>

![image](https://github.com/user-attachments/assets/7329a40e-37ea-43b7-9b97-d291936e0552)

<p>
    2.  Suspicious File Paths: <br>
      • %USERPROFILE%\AppData\Local\Google\Chrome\User Data <br>
      • %USERPROFILE%\AppData\Local\Steam <br>
      • %USERPROFILE%\AppData\Roaming\Mozilla\Firefox <br>
      • File types: *.txt, *.doc*, *key*, *wallet* <br>
<br>
      3. Targeted Applications: <br>
      • Browsers: Chrome, Firefox, Opera, Edge <br>
      • Messaging/Communication Apps: Discord, Telegram <br>
      • Gaming Clients: Steam <br>
      • VPN Software and Wallets: Potential exfiltration of cryptocurrency data.
</p>

![image](https://github.com/user-attachments/assets/56e476fa-6dea-40c2-8d19-ce7db11c7c70)

<p>
    4. Suspicious DNS Requests:
      - api.ip.sb (used to determine the victim's IP) <br>
</p>

![image](https://github.com/user-attachments/assets/d3cd54a8-ecff-4041-8883-251f067a9a19)

<h2>Methodology</h2>
<p>
  • Used Wireshark Statistics > Protocol Hierarchy to identify the dominant protocols. <br>
	• Examined Statistics > Conversations for suspicious external communication. <br>
	• Filtered DNS traffic to check for anomalous domain resolutions. <br>
  • Investigated HTTP POST requests for signs of data exfiltration.
</p>

<h2>Key Findings</h2>

  <h3>Malware Reconnaissance Activity:</h3> <br>
<p>
	• The infected machine (10.0.23.101) made DNS requests to api.ip.sb, a service commonly used to retrieve public IP addresses. <br>
	• This behavior suggests that the malware may be performing network reconnaissance to determine the external IP address of the infected host. <br><br>
The information gathered may be used for geolocation filtering or to adjust its attack strategy based on the victim’s location.
</p>

![image](https://github.com/user-attachments/assets/ffa61179-a35c-416f-90dc-2d8f0a8b568e)
![image](https://github.com/user-attachments/assets/0b80e13c-71c2-4698-8932-5754cf0681ba)

<h3>Payload Analysis</h3>
<p>
  The POST request contains a SOAP envelope with a detailed response structure for EnvironmentSettingsResponse. This response configuration includes the following key elements: <br><br>
	• BlockedCountry and BlockedIP: The malware is likely designed to avoid detection or targeting certain countries/IPs. <br>
	• Scan Parameters: The malware is instructed to scan specific browser directories, file paths, and applications for sensitive data such as credentials, keys, wallets, and documents. <br><br>
	
Scan for Applications: The configuration includes scanning for installed browsers (Chrome, Firefox, etc.), messaging platforms (Discord, Telegram), and applications like Steam and VPNs.
</p>
<h3>The purpose of the communication appears to be the following:</h3>
<p>
  • Data Exfiltration: Scanning for sensitive data, including credentials, crypto wallet files, and other personal information from specific applications and file directories. <br>
	• Credential Harvesting: Targeting browsers and other applications that may store sensitive information such as login credentials. <br>
	• Potential Malware Commanding: The SOAP response seems to be configuring malware behavior on the infected system, detailing the locations to scan for sensitive data and indicating how to exfiltrate it.
</p>

![image](https://github.com/user-attachments/assets/33888834-5b51-4f25-ab39-12ab65c48e8e)
![image](https://github.com/user-attachments/assets/0a8e2c76-b3b8-416c-b0c4-1ee8954949d9)

<h2>Recommendations:</h2>
<h3>Immediate Response (Containment)</h3>
<p>
	• Isolate 10.0.23.101 from the network. <br>
	• Block outbound traffic to 188.190.10.10 at the firewall. <br>
	• Force password resets for any accounts that may have been compromised.
</p>
<h3>Forensic Analysis</h3>
<p>
	• Dump process memory for malware artifacts. <br>
	• Check persistence mechanisms (scheduled tasks, registry keys). <br>
</p>
<h3>Long-Term Mitigation</h3>
<p>
	• Implement endpoint monitoring (EDR solutions) to detect similar threats. <br>
	• Conduct security awareness training for users (especially about phishing and credential theft). <br>
	• SIEM correlation rules: Set alerts for outbound traffic to 188.190.10.10 or SOAP requests from non-legitimate sources.
</p>

<h2>Conclusion</h2>
<p>
  The POST request and subsequent SOAP payload are consistent with a targeted data exfiltration campaign.<br>
  The malware is likely designed to collect and send sensitive information, including credentials and cryptocurrency wallet data, back to <br>
  the attacker. Immediate containment and further analysis are essential to fully understand the impact of this incident and prevent further compromise.

</p>
