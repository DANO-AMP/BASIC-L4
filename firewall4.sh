Install these first



apt install nload
-----------------
apt install tcpdump
-------------------
apt install dstat
-----------------
apt install ipset
-----------------




HOW TO SAVE IP TABLES 

iptables-save
USE THIS AFTER ADDING THE TABLES


________________________________
FIRST STEP appylying basic tables]
---------------------------------


### 1: Drop invalid packets ###
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
-----------------------------------------------------------------------
### 2: Drop TCP packets that are new and are not SYN ###
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
----------------------------------------------------------------------------------
### 3: Drop SYN packets with suspicious MSS value ###
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
------------------------------------------------------------------------------------------------------
### 4: Block packets with bogus TCP flags ###
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
### 5: Block spoofed packets ###
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
---------------------------------------------------------------
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
------------------------------------------------------------------------------------------------------
echo "Reject Spoofed Packets"

iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP

iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP
-------------------------------------------
echo "Block Packets With Bogus TCP Flags"

iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 10000 -s 192.168.1.0/24 -j ACCEPT
------------------------------------------------------------------
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
-----------------------------------------------------------------------------------------------
__________________________________
NEXT STEP adding patches/ip ranges]
----------------------------------
# udprape ranges
ipset -N udprape nethash
ipset -q -A udprape 155.133.246.0/23
ipset -q -A udprape 155.133.248.0/24
ipset -q -A udprape 162.254.192.0/24
ipset -q -A udprape 162.254.193.0/24
ipset -q -A udprape 13.107.14.0/24
ipset -q -A udprape 52.112.0.0/14
ipset -q -A udprape 216.58.215.0/24
ipset -q -A udprape 216.239.36.0/24
ipset -q -A udprape 67.199.248.0/24
ipset -q -A udprape 66.249.64.0/20
ipset -q -A udprape 163.172.0.0/16
ipset -q -A udprape 50.22.130.64/27
ipset -q -A udprape 211.239.128.0/18
ipset -q -A udprape 217.72.192.0/20
ipset -q -A udprape 77.247.111.0/24
ipset -q -A udprape 37.49.231.0/24
ipset -q -A udprape 37.49.228.0/24
----------------------------------
# cloudflare ranges
ipset -N cloudflare nethash
ipset -q -A cloudflare 173.245.48.0/20
ipset -q -A cloudflare 103.21.244.0/22
ipset -q -A cloudflare 103.22.200.0/22
ipset -q -A cloudflare 103.31.4.0/22
ipset -q -A cloudflare 141.101.64.0/18
ipset -q -A cloudflare 108.162.192.0/18
ipset -q -A cloudflare 190.93.240.0/20
ipset -q -A cloudflare 188.114.96.0/20
ipset -q -A cloudflare 197.234.240.0/22
ipset -q -A cloudflare 198.41.128.0/17
ipset -q -A cloudflare 162.158.0.0/15
ipset -q -A cloudflare 104.16.0.0/12
ipset -q -A cloudflare 172.64.0.0/13
ipset -q -A cloudflare 131.0.72.0/22
------------------------------------
# mangle rules that cover some tcp & udp floods before checking the connection state in the input chain.
iptables -A PREROUTING -t mangle -p UDP -m comment --comment "non dns traffic from cloudflare" -m set --match-set cloudflare src ! --sport 53 -d [put server ip here] -j DROP
iptables -A PREROUTING -t mangle -p UDP -m comment --comment "whitelisted udp ips on the game" -m set --match-set udprape src -d [put server ip here] -j DROP
--------------------------------------------------------------------------------------------------------------------------------------------------------------
# close ssh port 22 but still can login to ssh by whitelist. [iphere] put home connection [ vpnporthere] put con port like 1194
iptables -I INPUT -p tcp --dport 22 -s IPHERE -j ACCEPT
iptables -I INPUT -p tcp --dport VPNPORTHERE -s 0.0.0.0/0 -j ACCEPT
iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP
iptables -P INPUT DROP
---------------------
ovh-nat patch

iptables -t mangle -A PREROUTING -s 217.224.179.122 -j DROP
DROP LENGTH
iptables -A INPUT -p tcp -m length --length 52 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p tcp -i eth0 ! -s 0.0.0.0/0 --dport 32992 -j DROP
BLOCK SOURCE PORT

iptables -A OUTPUT -p tcp --dport 14335 -j DROP

iptables -t mangle -A PREROUTING -s 77.87.34.51 -j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 52 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p udp -i eth0 ! -s 0.0.0.0/0 --dport 43193 -j DROP
BLOCK SOURCE PORT3
iptables -A OUTPUT -p udp --dport 14335 -j DROP
-----------------------------------------------
ovh-vip patch

iptables -t mangle -A PREROUTING -s 46.201.226.158 -j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 740 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p udp -i eth0 ! -s 0.0.0.0/0 --dport 10000 -j DROP
BLOCK SOURCE PORT
iptables -A OUTPUT -p tcp --dport 14335 -j DROP


iptables -t mangle -A PREROUTING -s 76.219.128.222 -j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 69 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p udp -i eth0 ! -s 0.0.0.0/0 --dport 33848 -j DROP
---------------------------------------------------------------------
ovh-killerv4 patch


iptables -t mangle -A PREROUTING -s 192.41.230.134 -j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 121 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p tcp -i eth0 ! -s 0.0.0.0/0 --dport 7001 -j DROP

BLOCK SOURCE PORT
iptables -A OUTPUT -p tcp --dport 14335 -j DROP

iptables -t mangle -A PREROUTING -s 134.107.3.41 -j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 121 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p udp -i eth0 ! -s 0.0.0.0/0 --dport 7001 -j DROP
BLOCK SOURCE PORT3
iptables -A OUTPUT -p udp --dport 14335 -j DROP
----------------------------------------------
nfo-bye patch



iptables -t mangle -A PREROUTING -s 106.108.20.227 -j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 60 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p tcp -i eth0 ! -s 0.0.0.0/0 --dport 5901 -j DROP
-------------------------------------------------------------------
udpbypass patch


iptables -t mangle -A PREROUTING -s 243.45.216.58-j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 49 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p udp -i eth0 ! -s 0.0.0.0/0 --dport 39356 -j DROP
BLOCK SOURCE PORT
iptables -A OUTPUT -p udp --dport 5353 -j DROP


iptables -t mangle -A PREROUTING -s 133.154.184.21 -j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 190 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p udp -i eth0 ! -s 0.0.0.0/0 --dport 38815 -j DROP
BLOCK SOURCE PORT3
iptables -A OUTPUT -p udp --dport 9987 -j DROP
---------------------------------------------
ovh-evil patch

iptables -t mangle -A PREROUTING -s 162.254.193.47 -j DROP
DROP LENGTH
iptables -A INPUT -p udp -m length --length 446 -j DROP
BLOCK DESTINATION PORTS
iptables -A INPUT -p udp -i eth0 ! -s 0.0.0.0/0 --dport 32733 -j DROP
BLOCK SOURCE PORT
iptables -A OUTPUT -p udp --dport 992 -j DROP


------------------------
NOT MINE 
echo "Patching Dos Attacks"

iptables -A INPUT -s 73.144.69.72 -j DROP

iptables -A INPUT -s 104.24.100.100 -j DROP

iptables -A INPUT -s 104.24.31.73 -j DROP

iptables -A INPUT -s 159.89.89.88 -j DROP

iptables -I INPUT -s 157.230.225.45 -j DROP

iptables -I INPUT -s 118.24.236.219  -j DROP

iptables -I INPUT -s 118.89.142.127  -j DROP

iptables -I INPUT -s 182.100.67.15  -j DROP

iptables -I INPUT -s 118.24.231.39  -j DROP

iptables -I INPUT -s 207.154.206.212  -j DROP

iptables -I INPUT -s 134.208.23.110  -j DROP

iptables -I INPUT -s 213.111.35.160  -j DROP

iptables -I INPUT -s 170.210.68.163  -j DROP

iptables -I INPUT -s 209.141.50.57  -j DROP

iptables -I INPUT -s 51.68.82.218  -j DROP

iptables -I INPUT -s 73.34.124.146  -j DROP

iptables -I INPUT -s 207.154.206.212  -j DROP

iptables -I INPUT -s 118.24.236.219  -j DROP

iptables -I INPUT -s 118.89.142.127  -j DROP

iptables -I INPUT -s 182.100.67.15  -j DROP

iptables -I INPUT -s 118.24.231.39  -j DROP

iptables -I INPUT -s 207.154.206.212  -j DROP

iptables -I INPUT -s 134.208.23.110  -j DROP

iptables -I INPUT -s 213.111.35.160  -j DROP

iptables -I INPUT -s 170.210.68.163  -j DROP

iptables -I INPUT -s 209.141.50.57  -j DROP

iptables -I INPUT -s 51.68.82.218  -j DROP

iptables -I INPUT -s 73.34.124.146  -j DROP

iptables -I INPUT -s 207.154.206.212  -j DROP

iptables -I INPUT -s 51.77.227.246 -j DROP
-----------------------------------------
ALSO NOT MINE
iptables -A INPUT -s 73.144.69.72 -j DROP

iptables -A INPUT -s 104.24.100.100 -j DROP

iptables -A INPUT -s 104.24.31.73 -j DROP

iptables -A INPUT -s 159.89.89.88 -j DROP

iptables -I INPUT -s 157.230.225.45 -j DROP

iptables -I INPUT -s 118.24.236.219  -j DROP

iptables -I INPUT -s 118.89.142.127  -j DROP

iptables -I INPUT -s 182.100.67.15  -j DROP

iptables -I INPUT -s 118.24.231.39  -j DROP

iptables -I INPUT -s 207.154.206.212  -j DROP

iptables -I INPUT -s 134.208.23.110  -j DROP

iptables -I INPUT -s 213.111.35.160  -j DROP

iptables -I INPUT -s 170.210.68.163  -j DROP

iptables -I INPUT -s 209.141.50.57  -j DROP

iptables -I INPUT -s 51.68.82.218  -j DROP

iptables -I INPUT -s 73.34.124.146  -j DROP

iptables -I INPUT -s 207.154.206.212  -j DROP

iptables -I INPUT -s 118.24.236.219  -j DROP

iptables -I INPUT -s 118.89.142.127  -j DROP

iptables -I INPUT -s 182.100.67.15  -j DROP

iptables -I INPUT -s 118.24.231.39  -j DROP

iptables -I INPUT -s 207.154.206.212  -j DROP

iptables -I INPUT -s 134.208.23.110  -j DROP

iptables -I INPUT -s 213.111.35.160  -j DROP

iptables -I INPUT -s 170.210.68.163  -j DROP

iptables -I INPUT -s 209.141.50.57  -j DROP

iptables -I INPUT -s 51.68.82.218  -j DROP

iptables -I INPUT -s 73.34.124.146  -j DROP

iptables -I INPUT -s 207.154.206.212  -j DROP

iptables -I INPUT -s 51.77.227.246 -j DROP
------------------------------------------
echo "Block All Packets From IP's Ending In .0.0

iptables -A INPUT -m u32 --u32 "12&0xFFFF=0" -j DROP



echo "Block Source Split Packets"

iptables -A INPUT -p udp -m u32 --u32 "26&0xFFFFFFFF=0xfeff" -j DROP



echo "Block DOS - Teardrop"

iptables -A INPUT -p UDP -f -j DROP



echo "Block Random Size Attacks"

iptables -A INPUT -p udp -m u32 --u32 "22&0xFFFF=0x0008" -j DROP



echo "Attempts to Block STD Attacks"

iptables -I INPUT -p udp -m udp -m string --hex-string "|7374640000000000|" --algo kmp --from 28 --to 29 -j DROP

	

echo "Block DDOS - Smurf"

iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -p ICMP --icmp-type echo-request -m pkttype --pkttype broadcast -j DROP
iptables -A INPUT -p ICMP --icmp-type echo-request -m limit --limit 3/s -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT



echo "NTP"

iptables -A INPUT -p udp --sport 123 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT



echo "Block DDOS - UDP-flood (Pepsi)"

iptables -A INPUT -p UDP --dport 7 -j DROP
iptables -A INPUT -p UDP --dport 19 -j DROP
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset



echo "DNS"

iptables -A INPUT -i eth0 -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

iptables -A INPUT -i eth0 -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT


echo "Block DDOS - SMBnuke"

iptables -A INPUT -p UDP --dport 135:139 -j DROP
iptables -A INPUT -p TCP --dport 135:139 -j DROP



echo "Block DDOS - Fraggle"

iptables -A INPUT -p UDP -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -p UDP -m limit --limit 3/s -j ACCEPT



echo "Block DDOS - Jolt"

iptables -A INPUT -p ICMP -f -j DROP



echo "Drop TS3 Booter Methods"

iptables -A PREROUTING -t raw -p udp --dport 9987 -m string --hex-string '|fa163eb402096ac8|' --algo kmp -j DROP
iptables -A PREROUTING -t raw -p udp --dport 9987 -m string --hex-string '|71f63813d5422309|' --algo kmp -j DROP



echo "Block UDP Methode NTP"

iptables -A INPUT -i lo -p udp --destination-port 123 -j DROP
iptables -A INPUT -p udp --source-port 123:123 -m state --state ESTABLISHED -j DROP
iptables -A INPUT -p UDP --dport 123:123 -j DROP
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT



echo "BLOCK THE DEVIL"

iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP



echo "Block All Packets Drom Ips Ending In 0.0"

iptables -A INPUT -m u32 --u32 "12&0xFFFF=0" -j DROP



echo "Stop Null Packets"

iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP



echo "Stop SYN-Flood Attacks"

iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

iptables -A INPUT -p TCP --syn -m iplimit --iplimit-above 9 -j DROP



echo "Stop XMAS Packets"

iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP



echo "SSH Brute-Force Protection"

iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP


echo "Block UDP"

iptables -I INPUT -p udp --dport 16000:29000 -m string --to 75 --algo bm --string 'HTTP/1.1 200 OK' -j DROP

iptables -I INPUT -p udp -m udp -m string --hex-string "|7374640000000000|" --algo kmp --from 28 --to 29 -j DROP

iptables -A INPUT -p udp -m u32 --u32 "6&0xFF=0,2:5,7:16,18:255" -j DROP

iptables -A INPUT -m u32 --u32 "12&0xFFFF=0xFFFF" -j DROP

iptables -A INPUT -m u32 --u32 "28&0x00000FF0=0xFEDFFFFF" -j DROP

iptables -A INPUT -m string --algo bm --from 28 --to 29 --string "farewell" -j DROP

iptables -A INPUT -p udp -m u32 --u32 "28 & 0x00FF00FF = 0x00200020 && 32 & 0x00FF00FF = 0x00200020 && 36 & 0x00FF00FF = 0x00200020 && 40 & 0x00FF00FF = 0x00200020" -j DROP

iptables -I INPUT -p udp -m udp -m string --hex-string "|53414d50|" --algo kmp --from 28 --to 29 -j DROP

iptables -A PREROUTING -t raw -p udp --dport 9987 -m length --length 0:32 -j DROP

iptables -A PREROUTING -t raw -p udp --dport 9987 -m length --length 2521:65535 -j DROP

iptables -A PREROUTING -t raw -p udp --dport 9987 -m length --length 98 -j DROP

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Echo "Packet Checker"


iptables -A CHECK1 -j DROP
iptables -N CHECK1


iptables -N CHECK1
iptables -A INPUT -p udp -m length --length 20 -j CHECK1
iptables -A CHECK1 -m recent --name longudp --rcheck 1 --hitcount 5 -j DROP
iptables -A CHECK1 -m recent --name longudp --1350 -j RETURN


iptables -N CHECK1
iptables -A INPUT -p udp -m length --length 20 -j CHECK1
iptables -A CHECK1 -m recent --name longudp --rcheck 1 --hitcount 5 -j DROP
iptables -A CHECK1 -m recent --name longudp --1460 -j RETURN


iptables -A INPUT -p all -m length --length 222
iptables -A CHECK1 -j DROP
iptables -N CHECK1
iptables -A INPUT -p all -m length --length 222
iptables -A CHECK1 -j DROP
iptables -N CHECK1
iptables -A INPUT -p all -m length --length 222
iptables -A CHECK1 -j DROP
iptables -N CHECK1
iptables -A INPUT -p all -m length --length 222
iptables -A CHECK1 -j DROP
iptables -N CHECK1
iptables: Chain already exists.
iptables -A INPUT -p all -m length --length 222
iptables -A INPUT -p all -m length --length 222
iptables -A CHECK1 -j DROP
iptables -N CHECK1

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

echo "Blocks People From Pinging Your Ovh"

iptables -A INPUT -d (IP)/32 -p icmp -m icmp --icmp-type 8 -j DROP

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

echo "Blocks Most Port Scanners"

iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A INPUT   -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
-------------------------------------------------------------------------------------------------------------
echo "Security Team Patch"

iptables -A OUTPUT ! -s 127.198.148.58/32 ! -d 127.77.75.129/32 -p icmp -m icmp --icmp-type 3/3 -m connmark ! --mark 0x7ba5407d -j DROP
iptables -A OUTPUT ! -s 127.231.45.126/32 ! -d 127.20.246.233/32 -p tcp -m tcp --sport 61001:65535 --tcp-flags RST RST -m connmark ! --mark 0x407ee413 -j DROP
--------------------------------------------------------------------------------------------------------------------------------------------------------------
echo "Security team Method Patch"

iptables -A INPUT -p tcp -ack -m length --length 52 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP #Yubina-Kill-ACK
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m limit --limit 50/s -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -m limit --limit 50/s -j DROP
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m limit --limit 50/s -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
----------------------------------------------------------------------------------------
echo "Botnet Attack Filters"

iptables -t raw -A PREROUTING -p udp -m length --length 65535 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-65535 packets/4
iptables -t raw -A PREROUTING -p udp -m length --length 60000 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-60000 packets/4
iptables -t raw -A PREROUTING -p udp -m length --length 30000 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-30000 packets/4
iptables -t raw -A PREROUTING -p udp -m length --length 10000 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-10000 packets/4
iptables -t raw -A PREROUTING -p udp -m length --length 4096 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-4096 packets/4
iptables -t raw -A PREROUTING -p udp -m length --length 1052 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-1052 packets/4
iptables -t raw -A PREROUTING -p udp -m length --length 1000 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-1052 packets/4
iptables -t raw -A PREROUTING -p udp -m length --length 912 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-912 packets/4
iptables -t raw -A PREROUTING -p udp -m length --length 540 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-540 packets/3
iptables -t raw -A PREROUTING -p udp -m length --length 55 -j DROP #Malicious Botnet-UDP Payload / a UDP flood of length-55 packets/1
iptables -t raw -A PREROUTING -p udp -m length --length 38 -j DROP #Malicious Botnet-UDP Payload / UDP flood/37
iptables -A PREROUTING -p udp -m length --length 0:28 -j DROP #Dropping Empty UDP Packets / Deemed Illegitimate Packets
iptables -A INPUT -p udp -m u32 --u32 "2&0xFFFF=0x2:0x0100" #Generic-UDP-Header-Sequence
iptables -A INPUT -p udp -m u32 --u32 "12&0xFFFFFF00=0xC0A80F00" -j DROP #Katura-UDP-Payload
iptables -A INPUT -p tcp -syn -m length --length 52 u32 --u32 "12&0xFFFFFF00=0xc838" -j DROP #Mikey-Shit-TCP
iptables -A INPUT -p udp -m length --length 28 -m string --algo bm --string "0x0010" -j DROP #Botnet UDP
iptables -A INPUT -p udp -m length --length 28 -m string --algo bm --string "0x0000" -j DROP #Botnet UDP
iptables -A INPUT -p tcp -m length --length 40 -m string --algo bm --string "0x0020" -j DROP #Botnet TCP
iptables -A INPUT -p tcp -m length --length 40 -m string --algo bm --string "0x0c54" -j DROP #Botnet TCP
iptables -A INPUT -p tcp -m length --length 40 -m string --algo bm --string "0x38d3" -j DROP #Botnet TCP
iptables -A INPUT -p tcp -ack -m length --length 52 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP #Yubina-Kill-ACK
iptables -A INPUT -p tcp -syn -m length --length 52 -m string --algo bm --string "0xc838" -m state --state ESTABLISHED  -j DROP 


#Reckless-Mikey-Shit-TCp
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP #Yubina-RST
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP #Random-TCP
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP #Random-TCP

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

echo "Long-INT"

iptables -A INPUT -m string --algo bm --string "" -j DROP #Empty Long IT/STR/PL
iptables -A INPUT -m string --algo bm --string "U" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings



iptables -A INPUT -m string --algo bm --string "\x77" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB\xDE\xB6" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB\xDE\xB6\xB1\x94" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB\xDE\xB6\xB1\x94\xD6" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB\xDE\xB6\xB1\x94\xD6\x7A\x6B" -j DROP #OVH-SMACK Bypass Strings/
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
USE WITH YOUR OWN CAUTION 

echo "Making All Spooky Packets Go To Google So They Can Deal With It Not Government VPN"
iptables -t mangle -A PREROUTING -s 8.8.8.8 -d 8.8.8.8
------------------------------------------------------
echo "Making Ports More Spookey"
iptables -A INPUT -p tcp -m multiport --destination-ports 100:60000 -j DROP
---------------------------------------------------------------------------

                                                                                                                           
