import subprocess
from scapy.all import *
from interfaces import get_interfaces

def block_mac_address(mac_address):
    fw_command = subprocess.Popen('which iptables', shell=True, stdout=subprocess.PIPE)
    fw_type = fw_command.stdout.read().decode('utf-8').strip()
    if fw_type:
        command = f"sudo iptables -A INPUT -m mac --mac-source {mac_address} -j DROP"
    else:
        command = f"sudo nft add rule ip filter input ether saddr {mac_address} drop"
    subprocess.Popen(command, shell=True)

def process_sniffed_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        originalmac = mac(packet[ARP].psrc)
        responsemac = packet[ARP].hwsrc
        if originalmac != responsemac:
            print("[*] ALERT!! You are under attack, the ARP table is being poisoned.!")
            block_mac_address(packet[ARP].hwsrc)

def mac(ipadd):
    arp_request = ARP(pdst=ipadd)
    br = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = br / arp_request
    list_1 = srp(arp_req_br, timeout=5, verbose=False)[0]
    return list_1[0][1].hwsrc

def main():
    interfaces = get_interfaces()
    for interface in interfaces:
        sniff(iface=interface, store=False, prn=process_sniffed_packet)

if __name__ == '__main__':
    main()