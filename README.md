# linux-packet-sniffer
Packet sniffer for linux using standard headers only and no additional networking libraries (such as libpcap).

Demo supports 15 protocols:
  - Ethernet
    - ARP
      - IPv4 and IPv6
        - ICMP
        - TCP
          - DNS
          - ECHO
          - HTTP
          - IMAP
          - POP3
          - SMTP
          - TELNET
        - UDP
          - DHCP
          - DNS
          - ECHO
