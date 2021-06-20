iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
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
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
sleep 2 #sleep statement
iptables -t mangle -A PREROUTING -p icmp -j DROP
iptables -t mangle -A PREROUTING -f -j DROP
iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP
echo Ahora bloqueando una buena parte de la conexión de China, lo siento, China. Has causado muchos problemas en el mundo.  
iptables -A INPUT -s 192.168.0.0/16 -j DROP
iptables -A INPUT -s 101.248.0.0/15	-j DROP
iptables -A INPUT -s 101.248.0.0/16 -j DROP
iptables -A INPUT -s 103.8.32.0/24 -j DROP 
iptables -A INPUT -s 106.0.4.0/22 -j DROP 
iptables -A INPUT -s 106.108.0.0/15 -j DROP	
iptables -A INPUT -s 106.110.0.0/15 -j DROP	
iptables -A INPUT -s 106.112.0.0/14 -j DROP	
iptables -A INPUT -s 106.112.0.0/16 -j DROP	
iptables -A INPUT -s 106.113.0.0/16 -j DROP	
iptables -A INPUT -s 106.114.0.0/16 -j DROP
iptables -A INPUT -s 106.115.0.0/16 -j DROP
iptables -A INPUT -s 106.116.0.0/15 -j DROP	
iptables -A INPUT -s 106.116.0.0/16 -j DROP	
iptables -A INPUT -s 106.117.0.0/16 -j DROP		 	
iptables -A INPUT -s 106.118.0.0/16 -j DROP		 	
iptables -A INPUT -s 106.119.0.0/16 -j DROP		 	
iptables -A INPUT -s 106.122.0.0/16 -j DROP		 	
iptables -A INPUT -s 106.123.0.0/16 -j DROP		 	
iptables -A INPUT -s 106.124.0.0/16 -j DROP		 	
iptables -A INPUT -s 106.125.0.0/16 -j DROP		 	
iptables -A INPUT -s 106.126.0.0/16 -j DROP		 	
iptables -A INPUT -s 106.127.0.0/16 -j DROP
iptables -A INPUT -s 106.16.0.0/15 -j DROP	
iptables -A INPUT -s 106.18.0.0/15 -j DROP	
iptables -A INPUT -s 106.224.0.0/14 -j DROP	
iptables -A INPUT -s 106.228.0.0/16 -j DROP	
iptables -A INPUT -s 106.229.0.0/16 -j DROP	
iptables -A INPUT -s 106.230.0.0/16 -j DROP	
iptables -A INPUT -s 106.32.0.0/16 -j DROP	
iptables -A INPUT -s 106.33.0.0/16 -j DROP
iptables -A INPUT -s 106.34.0.0/16 -j DROP
iptables -A INPUT -s 106.35.0.0/16 -j DROP	
iptables -A INPUT -s 106.36.0.0/16 -j DROP	
iptables -A INPUT -s 106.40.0.0/16 -j DROP	
iptables -A INPUT -s 106.4.0.0/15 -j DROP
iptables -A INPUT -s 106.41.0.0/16 -j DROP	
iptables -A INPUT -s 106.42.0.0/16 -j DROP
iptables -A INPUT -s 106.43.0.0/16 -j DROP	
iptables -A INPUT -s 106.44.0.0/16 -j DROP	
iptables -A INPUT -s 106.45.0.0/16 -j DROP
iptables -A INPUT -s 106.46.0.0/16 -j DROP
iptables -A INPUT -s 106.56.0.0/15 -j DROP
iptables -A INPUT -s 106.58.0.0/15 -j DROP
iptables -A INPUT -s 106.60.0.0/15 -j DROP
iptables -A INPUT -s 106.6.0.0/16 -j DROP	
iptables -A INPUT -s 106.62.0.0/16 -j DROP
iptables -A INPUT -s 106.7.0.0/16 -j DROP	
iptables -A INPUT -s 106.80.0.0/15 -j DROP
iptables -A INPUT -s 106.8.0.0/16 -j DROP	
iptables -A INPUT -s 106.82.0.0/15 -j DROP	
iptables -A INPUT -s 106.84.0.0/15 -j DROP	
iptables -A INPUT -s 106.86.0.0/15 -j DROP	
iptables -A INPUT -s 106.88.0.0/15 -j DROP	
iptables -A INPUT -s 106.90.0.0/15 -j DROP	
iptables -A INPUT -s 106.9.0.0/16 -j DROP	
iptables -A INPUT -s 106.92.0.0/16 -j DROP	
iptables -A INPUT -s 110.152.0.0/14 -j DROP
iptables -A INPUT -s 110.156.0.0/15 -j DROP
iptables -A INPUT -s 110.166.0.0/15 -j DROP
iptables -A INPUT -s 110.176.0.0/13 -j DROP
iptables -A INPUT -s 110.184.0.0/13 -j DROP
iptables -A INPUT -s 110.190.90.0/24 -j DROP
iptables -A INPUT -s 110.190.91.0/24 -j DROP
iptables -A INPUT -s 110.190.92.0/24 -j DROP 
iptables -A INPUT -s 110.190.94.0/24	-j DROP 
iptables -A INPUT -s 110.80.0.0/13 -j DROP
iptables -A INPUT -s 110.88.0.0/14 -j DROP
iptables -A INPUT -s 111.112.0.0/15 -j DROP	
iptables -A INPUT -s 111.120.0.0/14 -j DROP	
iptables -A INPUT -s 111.124.0.0/16 -j DROP	
iptables -A INPUT -s 111.126.0.0/15 -j DROP	
iptables -A INPUT -s 111.170.0.0/16 -j DROP	
iptables -A INPUT -s 111.172.0.0/14 -j DROP	
iptables -A INPUT -s 111.176.0.0/13 -j DROP	
iptables -A INPUT -s 111.224.0.0/14 -j DROP	
iptables -A INPUT -s 111.72.0.0/13 -j DROP	
iptables -A INPUT -s 112.100.0.0/14 -j DROP
iptables -A INPUT -s 112.112.0.0/14 -j DROP
iptables -A INPUT -s 112.112.162.0/24 -j DROP
iptables -A INPUT -s 112.116.0.0/15 -j DROP
iptables -A INPUT -s 112.66.0.0/15 -j DROP	
iptables -A INPUT -s 112.98.0.0/15 -j DROP
iptables -A INPUT -s 113.112.0.0/13 -j DROP	
iptables -A INPUT -s 113.120.0.0/13 -j DROP
iptables -A INPUT -s 113.12.0.0/14 -j DROP
iptables -A INPUT -s 113.128.0.0/15 -j DROP
iptables -A INPUT -s 113.132.0.0/14 -j DROP	
iptables -A INPUT -s 113.136.0.0/13 -j DROP	
iptables -A INPUT -s 113.16.0.0/15 -j DROP		
iptables -A INPUT -s 113.214.0.0/15 -j DROP
iptables -A INPUT -s 113.218.0.0/15 -j DROP	
iptables -A INPUT -s 113.220.0.0/14 -j DROP	
iptables -A INPUT -s 113.240.0.0/13 -j DROP	
iptables -A INPUT -s 113.24.0.0/14 -j DROP	
iptables -A INPUT -s 113.248.0.0/14 -j DROP	
iptables -A INPUT -s 113.59.224.0/22 -j DROP	
iptables -A INPUT -s 113.62.0.0/15 -j DROP
iptables -A INPUT -s 113.64.0.0/11 -j DROP	
iptables -A INPUT -s 113.96.0.0/12 -j DROP	
iptables -A INPUT -s 114.104.0.0/14 -j DROP
sleep 2 #sleep statement
# Reject spoofed packets
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
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp -j DROP
sleep 2 
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP 
iptables -A INPIT -p tcp --tcp-flags ALL NONE -j DROP 
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP 
iptables -A INPUT -f -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp -m limit --limit 1/second -j ACCEPT
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j portscan
iptables -A INPUT -m recent --name UDP_FLOOD --rcheck --seconds 86400 -j portscan 
iptables -A INPUT -p tcp -m tcp -m recent -m state --state NEW --name portscan --set -j portscan 
iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 10/sec --limit-burst 15 -j ACCEPT
iptables -A INPUT -p tcp --sport 80 --syn -m state --state NEW -m limit --limit 10/sec --limit-burst 15 -j ACCEPT
iptables -t mangle -I PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK --sport XMR DROP
iptables -t mangle -I PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK --sport 80 --dport 30000:60000 -m length --length 44 -m string --hex-string '|00004000|' --algo kmp -j DROP 
iptables -t mangle -I PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK --sport XMRDROP 
iptables -t mangle -I PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK --sport XMR DROP 
iptables -t mangle -I PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK --sport 80 --dport 30000:60000 -m length --length 0 -m string --hex-string '|00004000|' --algo kmp -j DROP 
iptables -t mangle -I PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK --sport 80 --dport 30000:60000 -m length --length 60 -m string --hex-string '|00004000|' --algo kmp -j DROP 
iptables -t mangle -A PREROUTING -p tcp --sport 80  -m length --length 60 -j DROP
iptables -t mangle -A PREROUTING -p tcp --sport 80  -m length --length 0 -j DROP
iptables -t mangle -A PREROUTING -p tcp --sport 443  -m length --length 60 -j DROP
iptables -t mangle -A PREROUTING -p tcp --sport 443  -m length --length 0 -j DROP
iptables -t mangle -A PREROUTING -p tcp --sport 443  -m length --length 44 -j DROP
iptables -t mangle -A PREROUTING -p tcp --sport 80  -m length --length 0 -j DROP
sleep 5
iptables -t mangle -A PREROUTING -p udp --sport 37810 -m comment --comment "DVR ATTACK"-j DROP # FN DROP
tables -t mangle -A PREROUTING -p udp --sport 7001 -m comment --comment "AFS ATTACK" -j DROP # OVH-KILL
iptables -I INPUT -p udp -m length --length 100:140 -m string --string "nAFS" --algo kmp -m comment --comment "AFS ATTACK" -j DROP # OVH-KILL
iptables -I INPUT -p udp -m length --length 100:140 -m string --string "OpenAFS" --algo kmp -m comment --comment "AFS ATTACK" -j DROP # OVH-KILL
iptables -t mangle -A PREROUTING -p udp --sport 17185 -m comment --comment "vxWorks-VoIP ATTACK" -j DROP # OVH-SLAP
iptables -t mangle -A PREROUTING -p udp -m multiport --sports 3072,3702 -m comment --comment "WSD ATTACK" -j DROP # 
iptables -t mangle -A PREROUTING -p tcp -m multiport --sports 3072,3702 -m comment --comment "WSD ATTACK" -j DROP # OVH-DOWNV2
iptables -t mangle -A PREROUTING -p udp --sport 3283 -m length --length 1048 -m comment --comment "ARD ATTACK" -j DROP # OVH-CRUSHV2
iptables -t mangle -A PREROUTING -p udp --sport 3283 -m length --length 1048 -m comment --comment "ARD ATTACK" -j DROP # OVH-CRUSHV1
iptables -t mangle -A PREROUTING -p udp --sport 177 -m comment --comment "XDMCP ATTACK" -j DROP # NFO-LAG
iptables -t mangle -A PREROUTING -p udp --sport 6881 -m length --length 320:330 -m comment --comment "BitTorrent ATTACK" -j DROP # NFO-CLAP
iptables -t mangle -A PREROUTING -p udp -m length --length 280:300 --sport 32414 -m comment --comment "PlexMediaServers ATTACK" -j DROP # R6-LAG
iptables -t mangle -I PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK --sport XMR DROP 
iptables -t mangle -I PREROUTING -p tcp --tcp-flags SYN,ACK 
iptables -A INPUT -m string --algo bm --hex-string "|c6 9a 0b c2 00 164|" -j DROP 
iptables -A INPUT -m string --algo bm --hex-string "|4d a3 c0 da 2a 84 0f da 50 184|" -j DROP 
iptables -A INPUT -m string --algo bm --hex-string "|34 89 5b 08 00 004|" -j DROP   
iptables -A INPUT -m string --algo bm --hex-string "|33 40 28 97 08 00 45 004|" -j DROP 
iptables -A INPUT -m string --algo bm --hex-string "|05 a0 9c a1 00 00 33 06 b1 39 33 0f 07 90 33 444|" -j DROP 
iptables -A INPUT -m string --algo bm --hex-string "|29 47 82 d3 04 51 bf a6 50 184|" -j DROP 
iptables -A INPUT -m string --algo bm --hex-string "|60 0a 33 8e fc 50 184|" -j DROP 
iptables -A INPUT -m string --algo bm --hex-string "|5d 4b 81 9d 0d d0 cab|" -j DROP
iptables -A INPUT -m string --algo bm --hex-string "|4b87bc1a68e6b8b35017|" -j DROP 
iptables -A INPUT -p udp -m u32 --u32 "22&0xFFFF=0x0008" -j DROP
iptables -A INPUT -m u32 --u32 "12&0xFFFF=0xFFFF" -j DROP
iptables -A INPUT -m u32 --u32 "28&0x00000FF0=0xFEDFFFFF" -j DROP
iptables -A INPUT -m string --algo bm --from 28 --to 29 --string "farewell" -j DROP
iptables -A INPUT -p udp -m u32 --u32 "28 & 0x00FF00FF = 0x00200020 && 32 & 0x00FF00FF = 0x00200020 && 36 & 0x00FF00FF = 0x00200020 && 40 & 0x00FF00FF = 0x00200020" -j DROP
iptables -I INPUT -p tcp -m tcp -m string --hex-string "|000000005010|" --algo kmp --from 28 --to 29 -m length --length 40 -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|53414d50|" --algo kmp --from 28 --to 29 -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|7374640000000000|" --algo kmp --from 28 --to 29 -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|00000000000000000000000000000000|" --algo kmp --from 32 --to 33 -j DROP
iptables -A INPUT -p udp -m udp -m string --algo bm --from 32 --to 33 --string "AAAAAAAAAAAAAAAA" -j DROP
iptables -A INPUT -p udp -m udp -m string --algo bm --from 28 --to 29 --string "0123456789ABCDE" -j DROP
iptables -A INPUT -m u32 --u32 "12&0xFFFF=0" -j DROP
iptables -A INPUT -p udp -m u32 --u32 "26&0xFFFFFFFF=0xfeff" -j DROP
iptables -A INPUT -p udp -m udp -m string --algo bm --from 44 --to 45 --string "0123456789" -j DROP
iptables -A INPUT -p udp -m udp -m string --algo bm --from 28 --to 29 --string "A cat is fine too" -j DROP
iptables -A INPUT -p udp -m udp -m string --algo bm --from 28 --to 29 --string "flood" -j DROP
iptables -A INPUT -m string --algo bm --from 32 --to 33 --string "q00000000000000" -j DROP
iptables -A INPUT -m string --algo bm --from 32 --to 33 --string "statusResponse" -j DROP
iptables -A INPUT -i lo -p udp --destination-port 123 -j DROP
iptables -A INPUT -p udp --source-port 123:123 -m state --state ESTABLISHED -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|ffffffff6765746368616c6c656e676520302022|" --algo kmp -j DROP
iptables -I INPUT -p udp --dport 16000:29000 -m string --to 75 --algo bm --string 'HTTP/1.1 200 OK' -j DROP


