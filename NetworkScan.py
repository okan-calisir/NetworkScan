import pyfiglet
import scapy.all as scapy
import optparse

result = pyfiglet.figlet_format("Network Scan")
print(result)

def get_user_input():
    parse_object=optparse.OptionParser()
    parse_object.add_option("-i","--ip",dest="ip_address")

    (user_input,arguments)=parse_object.parse_args()

    if not user_input.ip_address:
        print("Please Enter IP Address!")

    return user_input

def scan(ip):
    arp_request_packet=scapy.ARP(pdst=ip)
    broadcast_packet=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    total_packet=broadcast_packet/arp_request_packet
    (answered_list,unanswered_list) = scapy.srp(total_packet,timeout=1)
    answered_list.summary()

user_ip_address = get_user_input()
scan(user_ip_address.ip_address)