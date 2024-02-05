# pcap_downloads.py
# pcap packet analysis script to find downloaded gifs
# working script for lab exercise
# adapted from: Violent Python Ch 4 (p136)
# Petra Leimich Nov 2016
# Change Log:
# Oct 17: Gaye Cleary - Python 3.6
# Nov 18: PL - Python 3.7 / PEP8
import socket
import dpkt


def find_download(pcap):
    """in current form, finds any gif files downloaded and prints
       request source (Downloader), gif URI and destination (provider) IP"""
    found = False
    for (time_s, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_ad = eth.data
            src = socket.inet_ntoa(ip_ad.src)
            dst = socket.inet_ntoa(ip_ad.dst)
            tcp = ip_ad.data

            http = dpkt.http.Request(tcp.data)
            if http.method == "GET":
                uri = http.uri.lower()
                if ".gif" in uri:
                    print(f"[!] {src} downloaded {uri} from {dst}")
                    found = True
        except Exception:
            # necessary as many packets would otherwise generate an error
            pass
    return found


def main():
    # should get results with filtered2.pcap but none with filtered3.pcap
    pcap_file = "filtered2.pcap"
    f = open(pcap_file, "rb")
    pcap = dpkt.pcap.Reader(f)

    print(f"[*] Analysing {pcap_file} for gif files")
    # call find_download which prints results
    result = find_download(pcap)
    if result is False:
        print("No gif downloads found in this file")


if __name__ == "__main__":
    main()
