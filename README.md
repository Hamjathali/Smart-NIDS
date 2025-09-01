# 🛡️ Smart AI-Based Network Intrusion Detection System (NIDS)

An **AI-powered, real-time Network Intrusion Detection System (NIDS)** built with **Deep Learning** and **Streamlit**.  
It captures network packets, extracts features, predicts intrusions using a trained **Conv1D model**, logs results, and can even block malicious IPs — all from a single script.

---

## 🚀 Features

- 📡 **Real-time Packet Capture** using Scapy (local)
- 📂 **PCAP File Support** via `capture_pcap.py` for Streamlit Cloud
- 🧠 **Deep Learning Intrusion Detection** with TensorFlow Conv1D
- 📊 **Streamlit UI** for live logging & visualization
- 📝 **Auto Logging to CSV** (`nids_log_streamlit.csv`)
- 🚫 **Auto IP Blocking** (optional firewall-level protection)
- ⚙️ **All-in-One Modular Script** (`smart_nids.py`)

---

## 🛠️ Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

> ⚠️ Requires **Python 3.11+**

---

## 🧠 Files & Structure

```
📂 SNIDS/
 ┣ 📜 smart_nids.py           # Main real-time NIDS script
 ┣ 📜 capture_pcap.py         # Helper script to save sample.pcap
 ┣ 📜 train_and_save_model.py # Script to train and save Conv1D model
 ┣ 🤖 conv1d_model.h5         # Trained deep learning model
 ┣ 📄 sample.pcap             # Sample packet file (for Streamlit Cloud)
 ┣ 📊 nids_log_streamlit.csv  # Output log file (auto-created)
 ┣ 📄 requirements.txt        # Project dependencies
 ┣ 🛑 .gitignore              # Ignore logs/models/cache/etc.
 ┗ 📦 get-pip.py              # (Optional) pip installer
```

---

## 📦 How to Run

### 🔹 Local Mode (Live Sniffing)
```bash
python smart_nids.py
```
Open in browser: **http://localhost:8501**

---

### 🔹 Streamlit Cloud Mode
1. Run `capture_pcap.py` locally to generate `sample.pcap`.  
2. Push `sample.pcap` to GitHub.  
3. Deploy to **Streamlit Cloud** → it will read packets from the `.pcap` file.

---

## ✅ Sample Output (Streamlit)

- ✅ **Normal Packet** → Logged in green  
- ❌ **Intrusive Packet** → Logged & (optionally) blocked  

---

## 🔐 Security Note

You can integrate the IP blocking function using:
- `iptables` (Linux)  
- PowerShell firewall commands (Windows)  

> ⚠️ Run with **admin/root privileges** when enabling blocking.

---

## 🙌 Credits

- 👨‍💻 Developed by: **Hamjathali I**  
- 💡 Idea: *AI-Driven Smart Intrusion Prevention*  
- 🛠️ Tech Stack: *Python, Scapy, TensorFlow, Streamlit*

---

## 📌 License

This project is open-source under the **MIT License**.
