🛡️ PRODIGY_CS_05 — Network Packet Analyzer
A lightweight, Python-based network packet analyzer designed for ethical cybersecurity learning and real-time packet inspection.

Developed using Scapy, this tool captures and analyzes live network traffic, showcasing essential details like source/destination IPs and protocol types (TCP/UDP).

📌 Features
🔍 Real-time packet capture

🌐 Display source and destination IP addresses

🔁 Detect and label protocols: TCP / UDP

⚙️ Secure and isolated execution via Python virtual environment

🐧 Optimized for Kali Linux and other Linux distros with root access

🧰 Requirements
✅ Python 3.10+ (PEP 668 compliant)

🐍 venv (virtual environment module)

📦 pip (Python package installer)

🧪 scapy (packet manipulation library)

🔐 Root privileges for packet capture

🐧 Kali Linux (or any Linux with suitable access)

⚙️ Setup Instructions (Kali Linux)
1️⃣ Clone the Repository
bash
Copy
Edit
git clone https://github.com/Akshay-kallada/PRODIGY_CS_05.git
cd PRODIGY_CS_05-Network-Packet-Analyzer
2️⃣ Create and Activate a Virtual Environment
bash
Copy
Edit
python3 -m venv .venv
source .venv/bin/activate
3️⃣ Install Dependencies
bash
Copy
Edit
python -m pip install --upgrade pip
pip install -r requirements.txt
✅ Compatible with PEP 668 (externally managed environments).
🔒 Avoid installing packages globally.

🚀 Running the Analyzer
Start the packet sniffer (requires root):

bash
Copy
Edit
sudo python3 sniffer.py
📤 Sample Output
css
Copy
Edit
[*] Starting Packet Sniffer... Press Ctrl+C to stop.
[TCP] 192.168.1.5 -> 172.217.11.14
[UDP] 192.168.1.5 -> 8.8.8.8
To stop the program:
Press Ctrl + C

📁 Project Structure
File	Description
sniffer.py	Main packet analyzer script
requirements.txt	Python dependency list
README.md	Project documentation

🔐 Ethical Use Notice
This tool is intended strictly for:

🎓 Educational and research purposes

🧪 Authorized environments and lab testing

👨‍💻 Learning real-world cybersecurity fundamentals

❌ DO NOT use this tool on public networks or unauthorized systems.
🔍 Always act responsibly and legally.