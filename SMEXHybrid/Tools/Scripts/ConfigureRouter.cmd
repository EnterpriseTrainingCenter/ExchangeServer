netsh interface ipv4 set address Internet static %1 255.255.255.192 78.142.168.129
netsh interface ipv4 add address Internet %2 255.255.255.192
netsh routing ip nat add addressrange Internet %1 %2 255.255.255.192
netsh routing ip nat add portmapping Internet tcp %1 53 10.1.1.1 53
netsh routing ip nat add portmapping Internet udp %1 53 10.1.1.1 53
netsh routing ip nat add portmapping Internet tcp %1 443 10.1.1.71 443
netsh routing ip nat add portmapping Internet tcp %2 25 10.1.1.20 25
netsh routing ip nat add portmapping Internet tcp %2 443 10.1.1.20 443
