#!/bin/bash


function reset_firewall {
    tables=('nat' 'mangle' 'raw' 'security')

    iptables -F
    iptables -X

    for table in "${tables[@]}"
    do
        iptables -t "$table" -F
        iptables -t "$table" -X
    done

    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    iptables-save > /etc/iptables/iptables.rules
}


function set_stateful_firewall {
    # Create tcp and udp chains.
    iptables -N TCP
    iptables -N UDP

    # Set the starting rules.
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    iptables -P INPUT DROP

    # Allow established traffic as well as valid new traffic.
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    #Disable outgoing ping
    #iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP

    #For Internet and IP
    iptables -A OUTPUT -p tcp -m tcp --dport 53 -m comment --comment "DNS-TCP" -j ACCEPT
    iptables -A OUTPUT -p udp -m udp --dport 53 -m comment --comment "DNS-UDP" -j ACCEPT
    iptables -A OUTPUT -p udp -m udp --dport 67:68 -m comment --comment "DHCP" -j ACCEPT

    iptables -A INPUT -p tcp -m tcp --dport 53 -m comment --comment "DNS-TCP" -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 53 -m comment --comment "DNS-UDP" -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 67:68 -m comment --comment "DHCP" -j ACCEPT



    iptables -A OUTPUT -p tcp -m tcp --dport 80 -m comment --comment "HTTP" -j ACCEPT
    iptables -A OUTPUT -p tcp -m tcp --dport 443 -m comment --comment "HTTPS" -j ACCEPT



    #Allow SSH but block incoming connexions
    iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
    #iptables -A INPUT -p tcp --sport 22 -j DROP

    # Allow traffic from the loopback device.
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    #Allow IRC Channel
    iptables -A INPUT -p tcp --dport 6667 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 6667 -j ACCEPT

    # Drop invalid packets.
    #iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # Reject pings.
    iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW \
        -j DROP

    # Attach the tcp and udp chains to the input chain.
    iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
    iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP

    # Reject tcp connections with rst packets and udp streams with port
    # unreachable messages.
    iptables -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
    iptables -A INPUT -p tcp -j REJECT --reject-with tcp-rst

    # Reject all remaining incoming traffic.
    iptables -A INPUT -j REJECT --reject-with icmp-proto-unreachable
    
    iptables-save > /etc/iptables/iptables.rules





}



function add_portscanner_rules {
    # syn scans.
    iptables -I TCP -p tcp -m recent --update --seconds 60 --name \
        TCP-PORTSCAN -j REJECT --reject-with tcp-rst
    iptables -D INPUT -p tcp -j REJECT --reject-with tcp-rst
    iptables -A INPUT -p tcp -m recent --set --name TCP-PORTSCAN -j REJECT \
        --reject-with tcp-rst

    # udp scans.
    iptables -I UDP -p udp -m recent --update --seconds 60 --name \
        UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable
    iptables -D INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
    iptables -A INPUT -p udp -m recent --set --name UDP-PORTSCAN -j REJECT \
        --reject-with icmp-port-unreachable

    # Restore final stateful rule.
    iptables -D INPUT -j REJECT --reject-with icmp-proto-unreachable
    iptables -A INPUT -j REJECT --reject-with icmp-proto-unreachable
}

case "$1" in
    stop)
        printf "\nResetting Firewall rules.\n"
        reset_firewall
        printf "\nFirewall disable.\n"
        ;;
    start)
        printf "\nFirewall up [OK].\n"
        set_stateful_firewall
	      printf "\nFirewall Block Port Scan [OK]\n"
	      add_portscanner_rules
        ;;
    *)
        echo "unrecognized command" ;;
esac
