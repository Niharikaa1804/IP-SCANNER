import scapy.all as scapy

def scan(ip_range, iface=None):
    # Create an ARP request packet
    arp_request = scapy.ARP(pdst=ip_range)
    # Create an Ethernet frame to broadcast the ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the ARP request and Ethernet frame
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and receive responses (use a specific interface if provided)
    print(f"Scanning IP range: {ip_range} on interface: {iface}")
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=iface)[0]

    devices = []
    if answered_list:
        for element in answered_list:
            device_info = {
                "ip": element[1].psrc,
                "mac": element[1].hwsrc
            }
            devices.append(device_info)
    else:
        print("No devices found. Check network and firewall settings.")

    return devices

def display_results(devices):
    if devices:
        print("IP Address\t\tMAC Address")
        print("-----------------------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
    else:
        print("No devices found in the network.")

if _name_ == "_main_":
    # Define the IP range to scan (adjust this to your network's range)
    ip_range = "192.168.1.1/24"  # Adjust based on your network range

    # Optional: Specify the network interface (e.g., "eth0", "wlan0")
    iface = "wlan0"  # Set to your network interface (use None if not sure)

    devices = scan(ip_range, iface)
    display_results(devices)