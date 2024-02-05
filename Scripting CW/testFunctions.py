def count_packet_pairs(packets, ip_packet):

    for packet_data in packets:
        src_ip = socket.inet_ntoa(ip_packet.src)
        dst_ip = socket.inet_ntoa(ip_packet.dst)
        pair = (src_ip, dst_ip)

        if pair in ip_pairs:
            ip_pairs[pair] += 1
        else:
            ip_pairs[pair] = 1

    # Sort the results by packet count in descending order
    sorted_ip_pairs = sorted(ip_pairs.items(), key=lambda x: x[1], reverse=True)

    # Print the results
    print("Sender-Destination IP Pairs:")
    for (src_ip, dst_ip), count in sorted_ip_pairs:
        print(f"From {src_ip} to {dst_ip}: {count} packets")

    return ip_pairs

    count_packet_pairs(packets)