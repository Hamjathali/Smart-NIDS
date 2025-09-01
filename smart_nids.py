import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import sniff, rdpcap, IP, TCP, UDP
from tensorflow.keras.models import load_model
from datetime import datetime
import os

import os
from scapy.all import sniff, rdpcap



def get_packets():
    try:
        # Try live sniffing (works in local with admin/root)
        return sniff(count=20)
    except Exception as e:
        # If sniff fails (Streamlit Cloud or no permission) → fallback
        
        if os.path.exists("sample.pcap"):
            return rdpcap("sample.pcap")
        else:
            
            return []

# Load pre-trained model
model = load_model("conv1d_model.h5")

# Store logs
packet_log = []

# Feature extractor
def extract_features(packet):
    try:
        proto = 0
        src_port = dst_port = length = flags = 0

        if IP in packet:
            length = len(packet)
            proto = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = int(packet[TCP].flags)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        return [proto, src_port, dst_port, length, flags]
    except:
        return [0, 0, 0, 0, 0]

# Predict and log
def predict_packet(packet):
    features = extract_features(packet)
    if sum(features) == 0:
        return None

    X = np.array(features).reshape(1, -1, 1)
    score = model.predict(X, verbose=0)[0][0]
    label = "INTRUSIVE" if score >= 0.5 else "NORMAL"
    ip = packet[IP].src if IP in packet else "Unknown"
    pkt_info = {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Label": label,
        "Score": round(float(score), 2),
        "IP": ip,
        "Info": packet.summary()
    }

    # Block malicious IP
    if label == "INTRUSIVE" and ip != "Unknown":
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        pkt_info["Blocked"] = True
    else:
        pkt_info["Blocked"] = False

    packet_log.append(pkt_info)
    return pkt_info

# Main streamlit interface
def main():
    st.title("🔐 Smart Network Intrusion Detection System")
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
        st.subheader("🔍 Packet Prediction Results")
        for pkt in packets:
            result = predict_packet(pkt)
            if result:
                st.write(f"**[{result['Time']}]** [{result['Label']}] - Score: {result['Score']} | IP: {result['IP']}")
                if result["Blocked"]:
                    st.error(f"Blocked IP: {result['IP']}")

        df = pd.DataFrame(packet_log)

        # Tabs for log filtering
        tab1, tab2 = st.tabs(["📘 Normal Packets", "🚨 Intrusive Packets"])
        with tab1:
            st.dataframe(df[df["Label"] == "NORMAL"])
        with tab2:
            st.dataframe(df[df["Label"] == "INTRUSIVE"])

        # Visualization
        st.subheader("📊 Intrusion Summary")
        chart_data = df["Label"].value_counts()
        fig, ax = plt.subplots()
        ax.pie(chart_data, labels=chart_data.index, autopct='%1.1f%%', colors=["green", "red"])
        ax.set_title("Packet Classification")
        st.pyplot(fig)

        # Save log
        df.to_csv("nids_log_streamlit.csv", index=False)
        st.success("Log saved to nids_log_streamlit.csv")
        
        st.markdown("---")  
        st.markdown("""
        ### 👨‍💻 Developed by: **Hamjathali I**  
        """)

        st.markdown(
            """
            <p style="font-size:20px;">💡 Idea: <i>AI-Driven Smart Intrusion Prevention</i></p>
            <p style="font-size:20px;">🛠️ Tech Stack: Python, Scapy, TensorFlow, Streamlit</p>
            """,
            unsafe_allow_html=True
        )



if __name__ == "__main__":
    main()