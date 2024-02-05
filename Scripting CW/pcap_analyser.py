"""
    Script: pcap_analyser.py
    Desc: open a packet capture file and parse it for specified information
    - IP addresses and email addresses 
    It will also perform some statistical analysis on the contents and visualise 
    the traffic flows
    Author: Sam McDonald Nov 2023

"""


from email_analysis import find_email
from email_analysis import find_ipv4
from datetime import datetime
import pandas as pd
from typing import List
import collections 
import statistics
from webpage_get import wget 
import dpkt
import matplotlib 
import networkx


#dynamically
def parse_file(ts, buf):

    eth = dpkt.ethernet.Ethernet(buf)

    timestamp = ts
    ip = eth.data
    traffic_type = ip.get_proto(ip.p).__name__
    packet_length = len(buf)
    payload = ip.data.data

    return {"timestamp": timestamp, "Traffic Type" : traffic_type, "packet length" : packet_length, "payload": payload, "ip" : ip}

def main() -> list[dict]:
    """main function"""
    pcap_file = "evidence-packet-analysis.pcap"
    open_file = open(pcap_file, "rb")
    pcap = dpkt.pcap.Reader(open_file)
    packets = []
    ip_pairs = {}

    print(f"[+] Analysing {pcap_file}")
    print("\n")

    for ts, buf in pcap:
        packet_data = parse_file(ts, buf)
        packets.append(packet_data)

    open_file.close()



    return packets, pcap

def analyze_traffic(packets):
    df = pd.DataFrame(packets)

    grouped_data = df.groupby("Traffic Type")

    summary_df = pd.DataFrame({
        "Number of Packets": grouped_data.size(),
        "First Timestamp": grouped_data["timestamp"].min(),
        "Last Timestamp": grouped_data["timestamp"].max(),
        "Mean Packet Length": grouped_data["packet length"].apply(statistics.mean)
    }).reset_index()

    summary_df["First Timestamp"] = summary_df["First Timestamp"].apply(lambda x: datetime.utcfromtimestamp(x).strftime('%Y-%m-%d %H:%M:%S'))
    summary_df["Last Timestamp"] = summary_df["Last Timestamp"].apply(lambda x: datetime.utcfromtimestamp(x).strftime('%Y-%m-%d %H:%M:%S'))

    return summary_df

#https://stackoverflow.com/questions/3682748/converting-unix-timestamp-string-to-readable-date


def extract_email(packets):
    to_list = []
    from_set = set()


    for packet_data in packets:
        payload = packet_data["payload"]

        packet_str = payload.decode('utf-8', errors='ignore')
        emails = find_email(packet_data["payload"])

        for email in emails:
            if 'TO' in packet_str:
                to_list.append(email)
            elif 'FROM' in packet_str:
                from_set.add(email)

    print("Email Addresses:")

    for em in to_list:
        print(f"TO: {em} ")

    for em in from_set:
        print(f"FROM: {em} ")

if __name__ == "__main__":
    packets, pcap = main()

    summary_df = analyze_traffic(packets)

    print(summary_df)
    print("\n")
    extract_email(packets)

