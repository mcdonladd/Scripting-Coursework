"""
Script: pcap_analyser2.py
Desc: Open a packet capture file and parse it for specified information
- IP addresses and email addresses 
It will also perform some statistical analysis on the contents and visualize 
the traffic flows
Author: Sam McDonald Nov 2023
"""

from datetime import datetime
from typing import List
import statistics
import re
import dpkt
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from ip_email_extractor import find_email, extract_ip_pairs


# Dynamically parse packet data
def parse_file(ts, buf):
    """
    Parse packet data

    Arguments:
        ts (float): Timestamp of the packet
        buf (bytes): Packet data

    Returns:
        dictionary: Parsed packet information
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        timestamp = ts
        ip = eth.data
        traffic_type = ip.get_proto(ip.p).__name__
        packet_length = len(buf)
        payload = ip.data.data

        return {
            "timestamp": timestamp,
            "Traffic Type": traffic_type,
            "packet length": packet_length,
            "payload": payload,
            "ip": ip,
        }

    except Exception as e:
        print(f"Error parsing packet: {e}")


# https://dpkt.readthedocs.io/en/latest/api/api_auto.html


def main() -> List[dict]:
    """
    Main function to process pcap file

    Returns:
        list: List of parsed packet data
    """
    pcap_file = "evidence-packet-analysis.pcap"
    packets = []
    try:
        with open(pcap_file, "rb") as open_file:
            pcap = dpkt.pcap.Reader(open_file)

            print(f"[+] Analysing {pcap_file}")
            print("\n")

            for ts, buf in pcap:
                packet_data = parse_file(ts, buf)
                packets.append(packet_data)

    except FileNotFoundError:
        print("Error: File not found")
    except dpkt.dpkt.NeedData:
        print("Error: Not enough data to parse the packet.")
    return packets


def analyze_traffic(packets):
    """
    Analyze traffic and create a summary DataFrame

    Args:
        packets (list): List of parsed packet data.

    Returns:
        pd.DataFrame: Summary DataFrame.
    """
    try:
        df = pd.DataFrame(packets)

        grouped_data = df.groupby("Traffic Type")

        summary_df = pd.DataFrame(
            {
                "Number of Packets": grouped_data.size(),
                "First Timestamp": grouped_data["timestamp"].min(),
                "Last Timestamp": grouped_data["timestamp"].max(),
                "Mean Packet Length": grouped_data["packet length"].apply(
                    statistics.mean
                ),
            }
        ).reset_index()

        summary_df = summary_df.assign(
            **{
                "First Timestamp": summary_df["First Timestamp"].apply(
                    lambda x: datetime.utcfromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")
                ),
                "Last Timestamp": summary_df["Last Timestamp"].apply(
                    lambda x: datetime.utcfromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")
                ),
            }
        )

        return summary_df

    except pd.errors.EmptyDataError as ede:
        print(f"Empty data error: {ede}")
    return None


def extract_email(packets):
    """
    function to extract email from packets

    Arguments:
        list: List of parsed packet data.
    """

    # using set to ensure every element is unique
    to_set = set()
    from_set = set()

    for packet_data in packets:
        payload = packet_data["payload"]

        packet_str = payload.decode("utf-8", errors="ignore")
        emails = find_email(packet_data["payload"])

        for email in emails:
            if "TO" in packet_str:
                to_set.add(email)
            elif "FROM" in packet_str:
                from_set.add(email)

    print("Email Addresses:")

    for em in to_set:
        print(f"TO: {em} ")

    for em in from_set:
        print(f"FROM: {em} ")


def extract_url(packets):
    """
    function to extract image urls and fielnames from packets

    Arguments:
        list: List of parsed packet data.
    """
    image_urls = []
    image_filenames = set()

    for packet_data in packets:
        payload = packet_data["payload"]

        packet_str = payload.decode("utf-8", errors="ignore")

        urls = re.findall(
            # https/https, domain and path, file extension
            r"(http[s]?://[a-zA-Z0-9/_.-]+\.(?:jpg|png|ico|jpeg|gif)|[a-zA-Z0-9/_.-]+\.(?:jpg|png|ico|jpeg|gif))",
            packet_str,
            # matches regardless of case
            re.IGNORECASE,
        )

        for url in urls:
            image_urls.append(url)

            # Extract filename a the last '/'
            filename = url.split("/")[-1]
            image_filenames.add(filename)

    print("\n")

    print("Image URLs:")
    for img_url in image_urls:
        print(img_url)

    print("\n")

    print("\nImage Filenames:")
    for img_filename in image_filenames:
        print(img_filename)

    print("\n")


def extract_ip_information(packets):
    """
    function to extract IP information

    Arguments:
        packets (list): List of parsed packet data.

    """
    # Extract IP pairs using function from 'ip_email_extractor.py' file
    ip_pairs_count = extract_ip_pairs(packets.copy())

    # Sort the IP pairs (on the second element)
    # https://blogboard.io/blog/knowledge/python-sorted-lambda/
    sorted_ip_pairs = sorted(ip_pairs_count.items(), key=lambda x: x[1], reverse=True)

    print("\nSender and Destination IP Address Pairs:")
    # Loop
    for ip_pair, count in sorted_ip_pairs:
        sender, destination = ip_pair
        print(f"Sender: {sender}, Destination: {destination}, Packet Count: {count}")

    print("\n")


def create_network_graph(ip_pairs_count):
    """
    Create a directed, weighted network graph only

    Arguments:
        ip_pairs_count (dict): Dictionary of IP address pairs and packet counts

    Returns:
        nx.DiGraph (graph)
    """
    graph = nx.DiGraph()

    for (sender, destination), count in ip_pairs_count.items():
        graph.add_edge(sender, destination, weight=count)

    return graph


def visualize_network_graph(graph):
    """
    Visualize the network graph and save it as a PNG file

    Arguments:
        graph
    """
    pos = nx.shell_layout(graph)

    # Different thickness and colouring to show how many packets are sent
    edge_thickness = [np.log(data["weight"]) for u, v, data in graph.edges(data=True)]
    line_color = nx.get_edge_attributes(graph, "weight").values()

    node_colors = "skyblue"

    nx.draw(
        graph,
        pos,
        with_labels=True,
        node_color=node_colors,
        width=edge_thickness,
        edge_color=line_color,
    )

    # statistics from graph
    print(f"Number of Nodes: {graph.number_of_nodes()}" + "\n")
    print(f"Number of Edges: {graph.number_of_edges()}" + "\n")
    print(f"Is Weakly Connected: {nx.is_weakly_connected(graph)}" + "\n")
    print(
        f"Weakly Connected Components: {list(nx.weakly_connected_components(graph))}"
        + "\n"
    )

    # Save the graph
    plt.savefig("network_graph.png")
    plt.show()


if __name__ == "__main__":
    parsed_packets = main()

    # .copy() to pass shallow copy in - original is unmodified
    summary_df = analyze_traffic(parsed_packets.copy())

    print(summary_df)
    print("\n")

    # calls extract email
    extract_email(parsed_packets.copy())

    # calls extract url
    extract_url(parsed_packets.copy())

    # calls extract ip
    extract_ip_information(parsed_packets.copy())

    # graph related functions
    ip_pairs_count = extract_ip_pairs(parsed_packets.copy())
    network_graph = create_network_graph(ip_pairs_count)
    visualize_network_graph(network_graph)
