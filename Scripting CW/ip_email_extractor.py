"""
    Script: url_email_extractor.py
    Desc: extracts email addresses and IPs from a file;
    for example, from a pcap file
    To work alongside pcap_analyser.py
    Author: Sam McDonald Nov 2023
"""
from typing import List
import re
import socket


def find_email(text: str) -> List[str]:
    """
    Finds To and From emails within text

    Arguments:
        text

    Returns:
        some emails
    """
    text_str = text.decode("utf-8", errors="ignore")

    emails = re.findall(

        #TO or From with optional whitespace, domain part, general domain name
        r"\b(?:TO|FROM)\s*([^\\\t\r\n]+[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.\w{2,4})",
        text_str,
    )

    return emails


def extract_ip_pairs(packets):
    """
    Extract sender and destination IP address pairs and count the number of packets for each pair.

    Arguments:
        packets (list): List of parsed packet data.

    Returns:
        dict: Dictionary containing sender and destination IP address pairs with packet counts.
    """
    ip_pairs_count = {}

    for packet_data in packets:
        # human readable
        src_ip = socket.inet_ntoa(packet_data["ip"].src)
        dst_ip = socket.inet_ntoa(packet_data["ip"].dst)

        # tuple as dictionary key
        ip_pair = (src_ip, dst_ip)

        # count
        ip_pairs_count[ip_pair] = ip_pairs_count.get(ip_pair, 0) + 1

    return ip_pairs_count