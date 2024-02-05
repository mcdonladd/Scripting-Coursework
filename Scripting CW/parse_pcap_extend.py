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


def main() -> None:
    """main function"""
    pcapfile = "filtered2.pcap"
    open_file = open(pcapfile, "rb")
    pcap = dpkt.pcap.Reader(open_file)

    for unused_ts, buf in pcap:
        # each tuple contains a timestamp, which we don't need here
        # prefixing the variable name with unused_ makes this clear and
        # avoids pylint W0612: Unused Variable warning
        eth = dpkt.ethernet.Ethernet(buf)

        # Add code here for Section 18

    open_file.close()


if __name__ == "__main__":
    main()
