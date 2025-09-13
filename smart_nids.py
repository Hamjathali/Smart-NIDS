# import streamlit as st
# import numpy as np
# import pandas as pd
# import matplotlib.pyplot as plt
# from scapy.all import sniff, rdpcap, IP, TCP, UDP
# from tensorflow.keras.models import load_model
# from datetime import datetime
# import os


# flow_tracker = {}

# def get_packets():
#     try:
#         # Try live sniffing (works in local with admin/root)
#         return sniff(count=20)
#     except Exception as e:
#         # If sniff fails (Streamlit Cloud or no permission) → fallback
        
#         if os.path.exists("sample.pcap"):
#             st.warning("⚠️ Live sniffing is disabled in Streamlit Cloud for data privacy, so we are using real-time data packets that were saved earlier and stored on GitHub.")
#             return rdpcap("sample.pcap")
#         else:
#             st.error("⚠️ Live sniffing not available and no real-time sample data packets are found.")
#             return []
            

# # Load pre-trained model
# model = load_model("binary_ids_model.h5")

# # Store logs
# packet_log = []

# # Feature extractor
# def extract_features(packet):
#     try:
#         proto = src_port = dst_port = length = flags = 0
#         flow_duration = packet_size_avg = 0

#         if IP in packet:
#             length = len(packet)
#             proto = packet[IP].proto
#             flow_id = (packet[IP].src, packet[IP].dst, proto)

#             # Track flow timestamps
#             now = datetime.now().timestamp()
#             if flow_id not in flow_tracker:
#                 flow_tracker[flow_id] = {'timestamps': [], 'sizes': []}
#             flow_tracker[flow_id]['timestamps'].append(now)
#             flow_tracker[flow_id]['sizes'].append(length)

#         if TCP in packet:
#             src_port = packet[TCP].sport
#             dst_port = packet[TCP].dport
#             flags = int(packet[TCP].flags)

#         elif UDP in packet:
#             src_port = packet[UDP].sport
#             dst_port = packet[UDP].dport

#         # Flow-based features
#         if 'flow_id' in locals() and flow_id in flow_tracker:
#             timestamps = flow_tracker[flow_id]['timestamps']
#             sizes = flow_tracker[flow_id]['sizes']
#             flow_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
#             packet_size_avg = np.mean(sizes)

#         # ✅ Only 7 features
#         return [proto, src_port, dst_port, length, flags, flow_duration, packet_size_avg]

#     except Exception as e:
#         print("Feature extraction error:", e)
#         return [0] * 7


# # Predict and log
# def predict_packet(packet):
#     features = extract_features(packet)
#     if sum(features) == 0:
#         return None

#     # ✅ Reshape correctly: 2D (1,7)
#     X = np.array(features).reshape(1, -1)

#     # Predict
#     score = model.predict(X, verbose=0)[0][0]
#     label = "INTRUSIVE" if score >= 0.5 else "NORMAL"

#     # Extract source IP if available
#     ip = packet[IP].src if IP in packet else "Unknown"

#     pkt_info = {
#         "Time": datetime.now().strftime("%H:%M:%S"),
#         "Label": label,
#         "Score": round(float(score), 2),
#         "IP": ip,
#         "Info": packet.summary()
#     }

#     # Block malicious IP
#     if label == "INTRUSIVE" and ip != "Unknown":
#         os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
#         pkt_info["Blocked"] = True
#     else:
#         pkt_info["Blocked"] = False

#     packet_log.append(pkt_info)
#     return pkt_info


# # Main streamlit interface
# def main():
#     st.title("🔐 Smart Network Intrusion Detection System")
#     mode = st.radio("Choose input method", ["Live Sniff (20 packets)", "Upload .pcap File"])

#     packets = []
#     if mode == "Live Sniff (20 packets)":
#         if st.button("Start Sniffing"):
#             with st.spinner("Sniffing..."):
#                 packets = get_packets()
#                 st.success("Packet capture complete.")
#     else:
#         uploaded = st.file_uploader("Upload a .pcap file", type=["pcap"])
#         if uploaded:
#             packets = rdpcap(uploaded)

#     if packets:
#         st.subheader("🔍 Packet Prediction Results")
#         for pkt in packets:
#             result = predict_packet(pkt)
#             if result:
#                 st.write(f"**[{result['Time']}]** [{result['Label']}] - Score: {result['Score']} | IP: {result['IP']}")
#                 if result["Blocked"]:
#                     st.error(f"Blocked IP: {result['IP']}")

#         df = pd.DataFrame(packet_log)

#         # Tabs for log filtering
#         tab1, tab2 = st.tabs(["📘 Normal Packets", "🚨 Intrusive Packets"])
#         with tab1:
#             st.dataframe(df[df["Label"] == "NORMAL"])
#         with tab2:
#             st.dataframe(df[df["Label"] == "INTRUSIVE"])

#         # Visualization
#         st.subheader("📊 Intrusion Summary")
#         chart_data = df["Label"].value_counts()
#         fig, ax = plt.subplots()
#         ax.pie(chart_data, labels=chart_data.index, autopct='%1.1f%%', colors=["green", "red"])
#         ax.set_title("Packet Classification")
#         st.pyplot(fig)

#         # Save log
#         df.to_csv("nids_log_streamlit.csv", index=False)
#         st.success("Log saved to nids_log_streamlit.csv")
        
#         st.markdown("---")


#         st.markdown(
#             """
#             <p style="font-size:20px; margin-top:0;">
#                 👨‍💻 Developed by: <b>Hamjathali I</b>
#             </p>
#             <p style="font-size:20px;">💡 Idea: <i>AI-Driven Smart Intrusion Prevention</i></p>
#             <p style="font-size:20px;">🛠️ Tech Stack: Python, Scapy, TensorFlow, Streamlit</p>
#             """,
#             unsafe_allow_html=True
#         )



# if __name__ == "__main__":
#     main()



import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import sniff, rdpcap, IP, TCP, UDP
from tensorflow.keras.models import load_model
from datetime import datetime, timedelta
import os

# ========================
# Globals
# ========================
flow_tracker = {}
packet_log = []
blocklist = {}  # { ip : unblock_time }
intrusion_counter = {}  # { ip : count }
BLOCK_TIMEOUT = 300  # seconds (5 minutes)

# ========================
# Packet Capture
# ========================
def get_packets():
    try:
        return sniff(count=20)
    except Exception:
        if os.path.exists("sample.pcap"):
            st.warning("⚠️ Live sniffing disabled in Streamlit Cloud. Using pre-saved packets.")
            return rdpcap("sample.pcap")
        else:
            st.error("⚠️ No live sniffing or sample.pcap available.")
            return []

# ========================
# Model
# ========================
model = load_model("binary_ids_model.h5")

# ========================
# Feature Extraction
# ========================
def extract_features(packet):
    try:
        proto = src_port = dst_port = length = flags = 0
        flow_duration = packet_size_avg = 0

        if IP in packet:
            length = len(packet)
            proto = packet[IP].proto
            flow_id = (packet[IP].src, packet[IP].dst, proto)

            now = datetime.now().timestamp()
            if flow_id not in flow_tracker:
                flow_tracker[flow_id] = {'timestamps': [], 'sizes': []}
            flow_tracker[flow_id]['timestamps'].append(now)
            flow_tracker[flow_id]['sizes'].append(length)

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = int(packet[TCP].flags)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if 'flow_id' in locals() and flow_id in flow_tracker:
            timestamps = flow_tracker[flow_id]['timestamps']
            sizes = flow_tracker[flow_id]['sizes']
            flow_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
            packet_size_avg = np.mean(sizes)

        return [proto, src_port, dst_port, length, flags, flow_duration, packet_size_avg]
    except:
        return [0] * 7

# ========================
# Prediction + Blocking
# ========================
def predict_packet(packet):
    features = extract_features(packet)
    if sum(features) == 0:
        return None

    X = np.array(features).reshape(1, -1)
    score = model.predict(X, verbose=0)[0][0]
    label = "INTRUSIVE" if score >= 0.5 else "NORMAL"

    ip = packet[IP].src if IP in packet else "Unknown"

    # --- Blocklist logic ---
    reason = ""
    blocked = False

    # Remove expired blocklist entries
    for blk_ip, expiry in list(blocklist.items()):
        if datetime.now() > expiry:
            del blocklist[blk_ip]

    if ip != "Unknown":
        if ip in blocklist:
            label = "BLOCKED"
            blocked = True
            reason = "Already in blocklist"
        elif label == "INTRUSIVE":
            blocklist[ip] = datetime.now() + timedelta(seconds=BLOCK_TIMEOUT)
            intrusion_counter[ip] = intrusion_counter.get(ip, 0) + 1
            blocked = True
            reason = "New intrusion detected"
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

    pkt_info = {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Label": label,
        "Score": round(float(score), 2),
        "IP": ip,
        "Info": packet.summary(),
        "Blocked": blocked,
        "Reason": reason
    }

    packet_log.append(pkt_info)
    return pkt_info

# ========================
# Streamlit UI
# ========================
def main():
    st.set_page_config(page_title="Smart NIDS", layout="wide")
    
    # Centered Title
    st.markdown(
        "<h1 style='text-align: center;'>🔐 Smart Network Intrusion Detection System</h1>",
        unsafe_allow_html=True
    )
    
    # Inject custom CSS for bigger text
    st.markdown("""
        <style>
        /* Increase font size of radio button labels */
        div[data-baseweb="radio"] label {
            font-size: 60px;
        }
        /* Increase font size of button text */
        div.stButton > button {
            font-size: 20px;
            height: 30px;
            width: 150px;
        }
        </style>
        """, unsafe_allow_html=True)

    # Use 3 columns to center content
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:  # Everything inside this column will be centered
        mode = st.radio("Choose input method", ["Live Sniff (20 packets)", "Upload .pcap File"])
        
        packets = []

        if mode == "Live Sniff (20 packets)":
            if st.button("Start Sniffing"):
                with st.spinner("Sniffing..."):
                    packets = get_packets()
                    st.success("Packet capture complete.")
        else:
            uploaded = st.file_uploader("Upload a .pcap file", type=["pcap"])
            if uploaded:
                packets = rdpcap(uploaded)

    if packets:
        for pkt in packets:
            predict_packet(pkt)

        df = pd.DataFrame(packet_log)

        # Sidebar stats
        st.sidebar.markdown("<h1 style='font-size:32px'>📊 System Stats</h1>", unsafe_allow_html=True)
        st.sidebar.metric("Total Packets", len(packet_log))
        st.sidebar.metric("Blocked Packets", sum(1 for p in packet_log if p.get("Blocked") == True))
        st.sidebar.metric("No of Unique IP Intrusions", len(intrusion_counter))

        # Logs
        st.subheader("📜 Packet Logs (last 20)")
        for pkt in packet_log[-20:][::-1]:
            if pkt["Label"] == "BLOCKED":
                st.error(f"[{pkt['Time']}] 🚫 BLOCKED | IP: {pkt['IP']} | Reason: {pkt['Reason']}")
            elif pkt["Label"] == "INTRUSIVE":
                st.warning(f"[{pkt['Time']}] ⚠️ INTRUSIVE | Score: {pkt['Score']} | IP: {pkt['IP']}")
            else:
                st.info(f"[{pkt['Time']}] ✅ NORMAL | Score: {pkt['Score']} | IP: {pkt['IP']}")

        # Data tabs
        tab1, tab2, tab3 = st.tabs(["📘 Normal", "🚨 Unique IP Intrusive", "🚫 Blocked"])
        with tab1:
            st.dataframe(df[df["Label"] == "NORMAL"])
        with tab2:
            st.dataframe(df[df["Label"] == "INTRUSIVE"])
        with tab3:
            st.dataframe(df[df["Label"] == "BLOCKED"])

        # Visualization
        st.subheader("📊 Intrusion Summary")
        chart_data = df["Label"].value_counts()
        fig, ax = plt.subplots(figsize=(3,3))
        ax.pie(chart_data, labels=chart_data.index, autopct='%1.1f%%', colors=["green", "orange", "red"])
        ax.set_title("Packet Classification")
        st.pyplot(fig, use_container_width=False)

        # Save log
        df.to_csv("nids_log_streamlit.csv", index=False)
        st.success("Log saved to nids_log_streamlit.csv")

        st.markdown("---")
        st.markdown(
            """
            <p style="font-size:20px; margin-top:0;">
                👨‍💻 Developed by: <b>Hamjathali I</b>
            </p>
            <p style="font-size:20px;">💡 Idea: <i>AI-Driven Smart Intrusion Prevention</i></p>
            <p style="font-size:20px;">🛠️ Tech Stack: Python, Scapy, TensorFlow, Streamlit</p>
            """,
            unsafe_allow_html=True
        )

if __name__ == "__main__":
    main()
