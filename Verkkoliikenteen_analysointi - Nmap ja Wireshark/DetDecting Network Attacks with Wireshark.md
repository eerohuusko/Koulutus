Detecting Network Attacks with Wireshark
===

In this excerise, we will be looking on Wireshark display filters and see how we could detect various network attacks with them in Wireshark.

We will be looking on a number of scenarios typically done by adversaries, e.g. various host discovery techniques, network port scanning methods, various network attacks such as denial of service, poisoning, flooding and also wireless attacks.

The purpose of this excerise is to provide a list of actionable and practical methods for detecting these network attacks using Wireshark filters.

So, Let’s get to it!

## Detection of host discovery (recon)

This section contains Wireshark filters that could help in identifying adversaries trying to find alive systems on our network.

Using these filters we should be able to detect various network discovery scans, ping sweeps and other things typically done during reconnaissance (asset discovery) phase.

Here’s the summary table with more details further down below:

![](https://gitlab.dclabra.fi/wiki/uploads/upload_6c77fba087693a61145868141accf98e.png)


## ARP scanning

Here’s a Wireshark filter to identify ARP scanning (host discovery technique on layer 2):

```arp.dst.hw_mac==00:00:00:00:00:00```

This is how ARP scanning looks like in Wireshark:

![](https://gitlab.dclabra.fi/wiki/uploads/upload_90b65533b19bab8183d7f7f751923c89.png)

During ARP scanning, an attacker is typically sending a large number of ARP requests on the broadcast (ff:ff:ff:ff:ff:ff) (255.255.255.255) destined to the MAC address 00:00:00:00:00:00 in order to **discover alive IP addresses on the local network**. We will typically see something like this:
```
Who has 192.168.0.1? Tell 192.168.0.53
Who has 192.168.0.2? Tell 192.168.0.53
Who has 192.168.0.3? Tell 192.168.0.53
Who has 192.168.0.4? Tell 192.168.0.53
Who has 192.168.0.5? Tell 192.168.0.53
````
In this case the attacker has IP address 192.168.0.53.

If we see many of these ARP requests in a short period of time asking for many different IP addresses, someone is probably trying to discover alive IPs on our network by ARP scanning (e.g. by running arp-scan -l).

## IP Protocol scan

Here’s a Wireshark filter to identify IP protocol scans:

```icmp.type==3 and icmp.code==2```

This is how IP protocol scan looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_c33018b0ed883819fe9e22b2fe8db0af.png)
IP protocol scanning is a technique allowing an attacker to discover which network protocols are supported by the target operating system (e.g. by running nmap -sO <target>).

During IP protocol scanning, we will likely see many ICMP type 3 (Destination unreachable) code 2 (Protocol unreachable) messages, because the attacker is typically sending a large number of packets with different protocol numbers.
    
## ICMP ping sweeps

Here’s a Wireshark filter to detect ICMP ping sweeps (host discovery technique on layer 3):

```icmp.type==8 or icmp.type==0```

This is how ICMP ping sweeping looks like in Wireshark:
    ![](https://gitlab.dclabra.fi/wiki/uploads/upload_965cc1ebc9785e4cce26ec095a55a419.png)
With this filter we are filtering ICMP Echo requests (type 8) or ICMP Echo replies (type 0).

If we see too many of these packets in a short period of time targeting many different IP addresses, then we are probably witnessing ICMP ping sweeps. Someone is trying to identify all alive IP addresses on our network (e.g. by running ```nmap -sn -PE <subnet>``` ).
    
## TCP ping sweeps

Here’s a Wireshark filter to detect TCP ping sweeps (host discovery technique on layer 4):

```tcp.dstport==7```

This is how TCP ping sweeping looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_e6895e84e7a92d6e459e5ccad5a565c2.png)

TCP ping sweeps typically use **port 7 (echo)**. 

If we see a higher volume of such traffic destined to many different IP addresses, it means somebody is probably performing TCP ping sweeping to find alive hosts on the network (e.g. by running ```nmap -sn -PS/-PA <subnet>``` ).
    
## UDP ping sweeps

Here’s a Wireshark filter to detect UDP ping sweeps (host discovery technique on layer 4):

```udp.dstport==7```

This is how UDP ping sweeping looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_a54428cbc369c80fae0830d38537abe1.png)
Similarly as TCP, UDP ping sweeps typically utilize **port 7 (echo)**.
If we see a high volume of such traffic destined to many different IP addresses, it means somebody is probably performing UDP ping sweeping to find alive hosts on the network (e.g. by running ```nmap -sn -PU <subnet> ```).
    
# Detection of network port scanning
    
This section contains Wireshark filters useful for identifying various network port scans, port sweeps etc.

Here’s the summary table with more details further down below:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_6a0c6bd934f20a677610fc781f1fc356.png)

## TCP SYN / stealth scan

Here’s a Wireshark filter to detect TCP SYN / stealth port scans, also known as TCP half open scan:

```tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024```

This is how TCP SYN scan looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_87af178bfbf52a9f2c259d4510f70b28.png)
                                                                      
In this case we are filtering out TCP packets with:

    SYN flag set
    ACK flag not set
    Window size <= 1024 bytes

This is basically a first step in the TCP 3-way handshake (the beginning of any TCP connection), with a very small TCP window size.

The small window size in particular is the characteristic parameter used by tools such as nmap or massscan during SYN scans, indicating that there will be essentially very little or no data.

If we see too many packets of this kind in a short period of time, someone is most likely doing:

* SYN scans in our network (e.g. by running ```nmap -sS <target>``` )
* SYN port sweeps across the network (e.g. by running ```nmap -sS -pXX <subnet>```)
* SYN floods (denial of service technique) 
    
## TCP Connect() scan

Here’s a Wireshark filter to detect TCP Connect() port scans:

```tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024```

This is how TCP Connect() scan looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_4e3c4ab6d798d524aafd7db875981de1.png)
In this case we are filtering out TCP packets with:

    SYN flag set
    ACK flag not set
    Window size > 1024 bytes

The only difference to SYN scans is the larger TCP window size, indicating a standard TCP connection, actually expecting some data to be transferred as well.

If we see too many packets of this kind in a short period of time, someone is most likely doing:

* Port scans in our network (e.g. by running ```nmap -sT <target>``` )
* Port sweeps across the network (e.g. by running ```nmap -sT -pXX <subnet>``` )
    
## TCP Null scan

Here’s a Wireshark filter to identify TCP Null scans:

```tcp.flags==0```

This is how TCP Null scan looks like in Wireshark:
    ![](https://gitlab.dclabra.fi/wiki/uploads/upload_731f0013a449cb798037bb2bc21ad264.png)
    
TCP Null scanning works by sending packets without any flags set. This could potentially penetrate some of the firewalls and discover open ports.

If we see packets like this in our network, someone is probably performing TCP null scans (e.g. by running ```nmap -sN <target>``` ).

## TCP FIN scan

Here’s a Wireshark filter to identify TCP FIN scans:

```tcp.flags==0x001```

This is how TCP FIN scan looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_37e43c7d20d22df46a1b9771b6d12050.png)

TCP FIN scans are characteristic by sending packets with only the FIN flag set. This could (again) potentially penetrate some of the firewalls and discover open ports.

If we see many packets like this in our network, someone is probably performing TCP FIN scans (e.g. by running ```nmap -sF <target>``` ).
    
## TCP Xmass scan

Here’s a Wireshark filter to detect TCP Xmass scans:

```tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1```

This is how TCP Xmass scan looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_b16958528d68d9dd5b92261f3e333138.png)
    
TCP Xmass scan work by sending packets with FIN, PUSH and URG flags set. This is yet another technique of penetrating some of the firewalls to discover open ports.

If we see such packets in our network, someone is probably performing TCP Xmass scans (e.g. by running ```nmap -sX <target>``` ).

## UDP port scan

Here’s a Wireshark filter to identify UDP port scans:

```icmp.type==3 and icmp.code==3```

This is how UDP port scan looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_da4ec71b599d7ff161df7c46dbf73bf7.png)
    
A good indicator of ongoing UDP port scanning is seeing high number of ICMP packets in our network, namely the ICMP type 3 (Destination unreachable) with code 3 (Port unreachable). These particular ICMP messages indicate that the remote UDP port is closed.

If we see a high number of these packets in our network in a short period of time, it most likely means someone is doing UDP port scans (e.g. by running ```nmap -sU <target> ```).

# Detection of network attacks
    
This excerise contains Wireshark filters useful for identifying various network attacks such as poisoning attacks, flooding, VLAN hoping etc.

Here’s the summary table with more details further down below:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_efdc1a8d59a9982adda41b8238b48942.png)
    
## ARP poisoning

Here’s a Wireshark filter to detect ARP poisoning:

```arp.duplicate-address-detected or arp.duplicate-address-frame```

This filter will display any occurrence of a single IP address being claimed by more than one MAC address. 
Such situation likely indicates that ARP poisoning is happening in our network.

ARP poisoning (also known as ARP spoofing) is a technique used to intercept network traffic between the router and other clients on the local network. 
It allows the attacker to perform **man-in-the-middle (MitM) attacks** on neigboring computers on the local network using tools such as arpspoof, ettercap and others.
    
## ICMP flood

Here’s how to detect ICMP flooding (denial of service technique) with Wireshark filter:

```icmp and data.len > 48```

This is how ICMP flood attack looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_d8dbf1d5820d1729a45f38b1e11ac57d.png)
    
A typical standard ICMP ping sends packets with 32 bytes of data (ping command on Windows) or 48 bytes (ping command on Linux).

When someone is doing ICMP flood, they typically send much larger data, so here we are filtering all ICMP packets with data size of more than 48 bytes. This will effectively detect any ICMP flooding regardless of the ICMP type or code.

Adversaries typically use tools such as **fping** or **hping** to perform ICMP flooding.
    
## VLAN hoping

Here’s a Wireshark filter for detecting VLAN hoping on the network:

```dtp or vlan.too_many_tags```

This is how VLAN hoping attack looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_2ac26c953ba6f40f4e4a6edade639165.png)
    
VLAN hoping is a technique for bypassing NAC (network access controls) often used by attackers trying to access different VLANs by exploiting misconfigurations of the Cisco switches.

A solid indicator of VLAN hoping is the presence of DTP packets or packets tagged with multiple VLAN tags.

If we see such packets in our network, someone might be attempting to do VLAN hoping e.g. by using **frogger** or **yersinia** utilities.

## Unexplained packet loss

Here’s filter for detecting packet loss on the network:

```tcp.analysis.lost_segment or tcp.analysis.retransmission```

If we see many packet re-transmissions and gaps in the network communication (missing packets), it may indicate that there is a severe problem in the network, possibly caused by a (distributed) denial of service (DDoS or DoS) attack.

# Detection of wireless network attacks

This excerise contains Wireshark filters useful for identifying various wireless network attacks such as deauthentication, disassociation, beacon flooding or authentication denial of service (DoS or DDoS) attacks.

Here’s the summary table with more details further down below:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_8c0afcecc2af1c7e86c48b726b28e30a.png)

## Client deauthentication

Here’s a Wireshark filter to detect deauthentication frames on wireless networks:

```wlan.fc.type_subtype == 12```

This is how wireless deauthentication attack looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_e64abb33e957e93199e53a0042cc2463.png)

Seeing the type 12 (deauthentication) frames in the air likely indicates that there is an attacker trying to deauthenticate other clients from the network in order to make them re-authenticate and consequently collect (sniff) the exchanged WPA / WPA2 4-way handshakes while they are re-authenticating.

This is a known technique for breaking into PSK (pre-shared key) based wireless networks. Once the attacker collects the 4-way WPA handshake, the attacker can then try to crack it and consequently obtain the cleartext password and access the network.

More information about deauthentication attacks can be found [here](https://www.aircrack-ng.org/doku.php?id=deauthentication).

## Client disassociation

Here’s a Wireshark filter to detect disassociation frames on wireless networks:

```wlan.fc.type_subtype == 10```

This is how wireless disassociation attack looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_9158722ad700da620af8b5e8d8648707.png)

Disassociation attack is another type of attack against PSK based wireless networks which works against WPA / WPA2. The idea behind this attack is that the attacker is sending type 10 (disassociation) frames which disconnects all clients from the target AP.

This could be even more effective for the attacker to collect the **[4-way handshake](https://en.wikipedia.org/wiki/IEEE_802.11i-2004#Four-way_handshakes)**. The attacker can (again) attempt to crack one of them and possibly obtain the cleartext password and access the network.

This type of attack can be carried out using tools such as **[mdk3](https://github.com/charlesxsh/mdk3-master)** or **[mdk4](https://github.com/aircrack-ng/mdk4)** (e.g. by running ```mdk4 wlan0mon d``` ).

## Authentication denial of service

Here’s a Wireshark filter to detect authentication denial of service attacks on wireless networks:

```wlan.fc.type_subtype == 11```

This is how wireless authentication DoS attack looks like in Wireshark:
![](https://gitlab.dclabra.fi/wiki/uploads/upload_abf7bb596fc3f11fee54ac2b25efbe64.png)

This type of attack works by flooding wireless access points in the area with many type 11 (authentication) frames, essentialy simulating a large number of clients trying to authenticate in the same time. This could overload some access points and potentially freeze or reset them and cause connectivity disruptions (jamming) in the area.

If we see a high number of type 11 frames in short period of time, someone could be performing authentication flooding in the area.

This type of attack can be carried out using tools such as **[mdk3](https://github.com/charlesxsh/mdk3-master)** or **[mdk4](https://github.com/aircrack-ng/mdk4)** (e.g. by running ```mdk4 wlan0mon a``` ).
    
# Conclusion

Wireshark is a very powerful tool when it comes to analyzing computer networks. There is number of protocol dissectors and filtering capabilities allow us to easily detect, visualize and study many different aspects of computer networks, not just from the cyber security perspective.