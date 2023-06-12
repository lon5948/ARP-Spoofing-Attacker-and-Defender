import os
import logging
import subprocess
from threading import Thread
from scapy.all import *
from interfaces import get_interfaces, get_gateway_ip

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='mitm_detector.log',
    filemode='a'
)

def send_notification(title, message):
    subprocess.run(["notify-send", title, message])


class DetectorMITMAttack:
   
    def __init__(self, interface: str, target_ip: str) -> None:
        self.interface = interface
        self.target_ip = target_ip

    def block_mac_address(self, mac_address: str) -> None:
        fw_command = subprocess.Popen('which iptables', shell=True, stdout=subprocess.PIPE)
        fw_type = fw_command.stdout.read().decode('utf-8').strip()
        if fw_type:
            command = f"sudo iptables -A INPUT -m mac --mac-source {mac_address} -j DROP"
        else:
            command = f"sudo nft add rule ip filter input ether saddr {mac_address} drop"
        subprocess.Popen(command, shell=True)

    def is_mitm_attack(self, packet: Packet) -> bool:
        if packet.haslayer(ARP):
            arp_packet = packet[ARP]

            if arp_packet.pdst != self.target_ip:
                return False

            if arp_packet.op == 2 and arp_packet.hwsrc != arp_packet.hwdst:
                print(f"\033[1;32m\033[1;32m[ATTENTION]\033[91m A potential MITM attack has been detected. \033[91m{arp_packet.hwsrc} ({arp_packet.psrc}) -> \033[1;32m\033[1;32m{arp_packet.hwdst} ({arp_packet.pdst})\033[0m")

                warn_message = f"A MITM attack has been detected: {arp_packet.hwsrc} ({arp_packet.psrc}) -> {arp_packet.hwdst} ({arp_packet.pdst})"
                send_notification(
                    "MITM Detector", 
                    warn_message
                )
                logging.warning(warn_message)

                self.block_mac_address(arp_packet.hwsrc)
                return True

        return

    def start_sniffing(self) -> None:
        print(f"\033[1;32m\033[1;32m[INFO]\033[91m\033[91m Start packet capture on the interface\033[0m {self.interface}")
        sniff(iface=self.interface, prn=self.is_mitm_attack)


def start_mitm_detection(interface, target_ip):
    mitm = DetectorMITMAttack(interface, target_ip)
    thread = Thread(target=mitm.start_sniffing)
    thread.start()


def main():
    '''
    interfaces = get_interfaces()
    default_gateway_ip = get_gateway_ip()

    print("Choose a startup option")
    print("1. Enter the network interface manually.")
    print(f"2. Startup on all network devices. \033[1;32m\033[1;32m(Обнаружены ({len(interfaces)}): {interfaces})\033[1;37m\033[1;37m")

    choice = input("\033[1;32m\033[1;32m~# \033[1;37m\033[1;37m")

    if choice == '1':
        print("\nPlease enter the name of the network interface: (e.g., wlan0)")
        interface = input("\033[1;32m\033[1;32m~# \033[1;37m\033[1;37m")
        start_mitm_detection(interface, default_gateway_ip)
    elif choice == '2':
    '''
    interfaces = get_interfaces()
    default_gateway_ip = get_gateway_ip()
    for interface in interfaces:
        start_mitm_detection(interface, default_gateway_ip)
    '''
    else:
        print("\033[1;32m[ERROR]\033[1;31m Неверный выбор\033[0m")
        return False
    '''

if __name__ == '__main__':
    main()