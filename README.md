# 🛡️ Smart AI-Based Network Intrusion Detection System (NIDS)

This project is an AI-powered, real-time Network Intrusion Detection System (NIDS) built using deep learning and Streamlit. It captures network packets, extracts meaningful features, predicts intrusions using a trained Conv1D model, logs the results, and even blocks malicious IPs — all from a single script.

---

## 🚀 Features

- 📡 **Real-time Packet Capture** using Scapy
- 🧠 **Deep Learning Intrusion Detection** with TensorFlow Conv1D
- 📊 **Streamlit UI** for live logging & visualization
- 📂 **Auto Logging to CSV** (`nids_log_streamlit.csv`)
- 🚫 **Auto IP Blocking** for malicious packets (optional firewall-level)
- ⚙️ All-in-One Modular Python Script (`smart_nids.py`)

---

## 🛠️ Requirements

Install dependencies using:

```bash
pip install -r requirements.txt
```

Make sure you have Python 3.11+ installed.

---

## 🧠 Files & Structure

```bash
SNIDS/
│
├── smart_nids.py                # Main real-time NIDS script
├── train_and_save_model.py      # Script to train and save Conv1D model
├── conv1d_model.h5              # Trained deep learning model
├── nids_log_streamlit.csv       # Output log file (auto-created)
├── requirements.txt             # Project dependencies
├── .gitignore                   # Ignore logs/models/cache/etc.
└── get-pip.py                   # (Optional) pip installer
```

---

## 📦 How to Run

```bash
python smart_nids.py
```

Then open your browser at:  
`http://localhost:8501`

You’ll see a live Streamlit dashboard with logs and predictions.


## ✅ Sample Output (Streamlit)

- ✅ Normal Packet → Log in green
- ❌ Intrusive Packet → Logged & (optionally) blocked

---

## 🔐 Security Note

You can integrate the IP blocking function using `iptables` (Linux) or PowerShell firewall commands (Windows). Make sure to run with appropriate admin privileges.

---

## 🙌 Credits

- 👨‍💻 Developed by: Hamjathali I  
- 💡 Idea: AI-Driven Smart Intrusion Prevention  
- 🛠️ Tech Stack: Python, Scapy, TensorFlow, Streamlit

---
## 📌 License

This project is open-source under the [MIT License](LICENSE).
"# Smart-NIDS" 
