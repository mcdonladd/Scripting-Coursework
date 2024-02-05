"""
    parse_pcap.py
    Basic Script to parse a pcap file with dpkt
    Adapted from:
    https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
    Mar 2021: function annotations, pylint

    For documentation on dpkt library, see....
    https://dpkt.readthedocs.io/en/latest/
"""
import dpkt

def parse_file():
    return 



def main(print_out=True, break_first=True) -> list:
    """main function"""
    pcap_file = "evidence-packet-analysis.pcap"
    open_file = open(pcap_file, "rb")
    pcap = dpkt.pcap.Reader(open_file)
    packets = []

    print(f"[+] Analysing {pcap_file}")

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if print_out:
            print(f"#<INFO> eth ethernet packet: {repr(eth)}\n")

        ip_ad = eth.data
        if print_out:
            print(f"#<INFO> eth.data: {repr(ip_ad)}")

        packets.append(eth)

        if break_first:  # stop after the first packet
            break

    open_file.close()
    return packets


if __name__ == "__main__":
    main()
