sudo iptables -A INPUT -s 10.192.1.101 -p tcp --dport 10000 -j MARK --set-mark 1 
sudo iptables -A INPUT -d 10.192.1.10 -p tcp --dport 10000 -j MARK --set-mark 1 
