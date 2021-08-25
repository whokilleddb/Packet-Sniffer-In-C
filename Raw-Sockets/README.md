<h1 align="center">Packet Sniffer In C</h1>
<h2 align="center">Using Raw Sockets</h2>
<p align="center">
<a href="./LICENSE.md"><img src="https://img.shields.io/badge/License-GPL%20v2-blue.svg"></a>
<img src="https://img.shields.io/badge/Made%20With-C-green.svg"></a>

<h2>Packet Sniffer</h2>
<p>Sniff Packets On An Interface Using Raw Sockets</p>

## Compiling
```bash
$ git clone https://github.com/whokilleddb/Packet-Sniffer-In-C
$ cd Packet-Sniffer-In-C/Raw-Sockets
$ make
```
_PS: This Program Requires Super User Privileges To Run_

## Example Usage

### Example 1:
```bash
# ./sniffer
[+] Packet Sniffer by @whokilleddb
[-] Incorrect Syntax
[+] Usage : ./sniffer [interface]
========== Available Interfaces ==========
lo	IPv4	127.0.0.1
wlp6s0	IPv4	192.168.0.103 (IEEE 802.11)
lo	IPv6	::1
wlp6s0	IPv6	fe80::8431:b74d:1195:281c (IEEE 802.11)
```
### Example 2:
```bash
# ./sniffer lo                                            
[+] Packet Sniffer by @whokilleddb
[+] Successfully Created Raw Socket
[+] Successfully Indexed lo
[+] Log File sniff.log

================= Packet =================
---------------- Ethernet ----------------
|- Source Address: 00:00:00:00:00:00
|- Destination Address: 00:00:00:00:00:00
|- Protocol: 8 (Internet Protocol packet)
------------------- IP -------------------
|- Version: IPv4
|- IP Header Length: 5 DWORDS or 20 Bytes
|- Type Of Service: 0
|- Total Length: 84 Bytes(Size of Packet)
|- Identification: 6053
|- TTL: 64
|- Protocol: 1 (Internet Control Message Protocol)
|- Checksum: 9474
|- Source IP: 127.0.0.1
|- Destination IP: 127.0.0.1
------------------ ICMP ------------------
|- Type: 8 (Echo)
|- Code: 0
|- Checksum: 48174
|- Packet Dump: 
 08 00 BC 2E 00 09 00 01 02 2C 26 61 00 00 00 00    .........,&a....
 51 67 03 00 00 00 00 00 10 11 12 13 14 15 16 17    Qg..............
 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27    ........ !"#$%&'
 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37    ()*+,-./01234567
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
 00 00                                              ..

```

_PS: This Program Requires Super User Privileges To Run_