from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, sniff

'''
Check 'Supported interface modes' for 'monitor':
iw list

iw wlp2s0 interface add mon0 type monitor
ifconfig mon0 up         

or

sudo airodump-ng --beacons wlp2s0

'''

ap_list = []
f= open("6metr.txt","w+")

def PacketHandler(pkt) :
    if pkt.haslayer(Dot11) :
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
			try:
				extra = pkt.notdecoded
				rssi = -(256-ord(extra[-2:-1]))
			except:
				rssi = -100
			print "WiFi signal strength:", rssi, "dBm of", pkt.addr2, pkt.info
			f.write("Addr: " + pkt.addr2 + " Name: " + pkt.info + " Strength: " + str(rssi))

sniff(iface="mon0", prn = PacketHandler)
f.close() 
