#include <stdio.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/ioctl.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

int getPacketSocket(const char* interfaceName)
{
   /*
      man 7 packet:

      SOCK_RAW - raw packets including the link-level header.
      They are passed to and from the device driver without any
      changes in the packet data.

      ETH_P_ALL - all protocols are received.

      All incoming packets of given protcol type will be passed to the
      packet socket before they are passed to the protocols implemented
      in the kernel.
   */
   uint16_t protocol = htons(ETH_P_ALL);

   int packetSocket = socket(AF_PACKET, SOCK_RAW, protocol);

   if(packetSocket == -1)
   {
      perror("getPacketSocket: socket error for (AF_PACKET, SOCK_RAW, ETH_P_ALL)");

      return -1;
   }

   unsigned int interfaceIndex = if_nametoindex(interfaceName);

   if(!interfaceIndex)
   {
      perror("getPacketSocket: if_nametoindex error");

      close(packetSocket);
      
      return -1;
   }

   /*
      man 7 packet:

      By default, all packets of the specified protocol type are passed to a packet socket.

      To get packets only from a specific interface use bind(2) specifying an address
      in a struct sockaddr_ll to bind the packet socket to an interface.

      Fields used for binding are sll_family (should be AF_PACKET), sll_protocol, and sll_ifindex.
   */
   struct sockaddr_ll buf =
   {
      .sll_family = AF_PACKET,
      .sll_protocol = protocol,
      .sll_ifindex = interfaceIndex
   };

   if(bind(packetSocket, (struct sockaddr*)&buf, sizeof buf) == -1)
   {
      perror("getPacketSocket: bind error");

      close(packetSocket);

      return -1;
   }

   printf("-> Bound to network interface %s (index: %u)\n", interfaceName, interfaceIndex);

   struct ifreq ifr = {};
   
   // man 7 netdevice:
   // ifr_name - interface name.
   strncpy(ifr.ifr_name, interfaceName, sizeof ifr.ifr_name - 1);

   // SIOCGIFFLAGS - get or set the active flag word of the device.
   if(ioctl(packetSocket, SIOCGIFFLAGS, &ifr) == -1)
   {
      perror("getPacketSocket: ioctl error for SIOCGIFFLAGS");
      
      close(packetSocket);

      return -1;
   }

   // set the flag only if not already set
   if(ifr.ifr_flags & IFF_PROMISC)
   {
      puts("\t* Network interface is already in promiscuous mode");

      return packetSocket;
   }

   // IFF_PROMISC - interface is in promiscuous mode.
   ifr.ifr_flags |= IFF_PROMISC;

   /*
      SIOCSIFFLAGS - set the active flag word of the device.
      Setting the active flag word is a privileged operation, but
      any process may read it.      
   */
   if(ioctl(packetSocket, SIOCSIFFLAGS, &ifr) == -1)
   {
      perror("getPacketSocket: ioctl error for (SIOCSIFFLAGS, IFF_PROMISC)");

      close(packetSocket);

      return -1;
   }

   puts("\t-> Successfully turned on promiscuous mode in the network interface");

   return packetSocket;
}

// higher layer protocols increase the `data` pointer (by adding header length of their packet)
// and decrease the `length` field (by subtracting header length of their packet)
typedef struct
{
   uint16_t length;
   const uint8_t* data;
} Payload;

void trimPayloadHeader(Payload* payload, uint16_t headerLength)
{
   payload->data += headerLength;
   payload->length -= headerLength;
}

void trimPayloadHeaderWithNewLength(Payload* payload, uint16_t headerLength, uint16_t payloadLength)
{
   payload->data += headerLength;
   payload->length = payloadLength;
}

#define ECHO_PORT   7
#define TELNET_PORT 23
#define SMTP_PORT   25
#define DNS_PORT    53
#define DHCP_PORT   67
#define HTTP_PORT   80
#define POP3_PORT   110
#define IMAP_PORT   143

// https://0x00sec.org/t/dns-header-for-c/618
struct dnshdr
{
	uint16_t id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
   uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t zero:3;
	uint16_t ra:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
   uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t zero:3;
	uint16_t rcode:4;
#else
   #error "Adjust your <bits/endian.h> defines"
#endif
	uint16_t qcount;	/* question count */
	uint16_t ancount;	/* Answer record count */
	uint16_t nscount;	/* Name Server (Autority Record) Count */ 
	uint16_t adcount;	/* Additional Record Count */
};

#define DECLARE_PROTOCOL_HEADER(HEADER_TYPE) const struct HEADER_TYPE* header = (struct HEADER_TYPE*)payload->data

#define DECLARE_PROTOCOL_HANDLER(PROTOCOL, ...) bool handle##PROTOCOL(Payload* payload, ##__VA_ARGS__)

DECLARE_PROTOCOL_HANDLER(DNS)
{
   DECLARE_PROTOCOL_HEADER(dnshdr);

   trimPayloadHeader(payload, sizeof *header);

   printf(
            "\t-> [DNS] id: %x qr: %u op: %u aa: %u tc: %u rd: %u ra: %u zero: %u rcode: %u "
            "count: [q: %u, an: %u, ns: %u, ad: %u]"
            "\n%*s\n",
            ntohs(header->id), header->qr, header->opcode, header->aa, header->tc, header->rd, header->ra, header->zero, header->rcode,
            ntohs(header->qcount), ntohs(header->ancount), ntohs(header->nscount), ntohs(header->adcount),
            payload->length, payload->data);
   
   return true;
}

// https://www.linuxquestions.org/questions/linux-networking-3/dhcp-structure-276446/
#define MAX_DHCP_CHADDR_LENGTH  16
#define MAX_DHCP_SNAME_LENGTH   64
#define MAX_DHCP_FILE_LENGTH    128
#define MAX_DHCP_OPTIONS_LENGTH 312

struct dhcphdr
{
   u_int8_t  op;                   /* packet type */
   u_int8_t  htype;                /* type of hardware address for this machine (Ethernet, etc) */
   u_int8_t  hlen;                 /* length of hardware address (of this machine) */
   u_int8_t  hops;                 /* hops */
   u_int32_t xid;                  /* random transaction id number - chosen by this machine */
   u_int16_t secs;                 /* seconds used in timing */
   u_int16_t flags;                /* flags */
   struct in_addr ciaddr;          /* IP address of this machine (if we already have one) */
   struct in_addr yiaddr;          /* IP address of this machine (offered by the DHCP server) */
   struct in_addr siaddr;          /* IP address of DHCP server */
   struct in_addr giaddr;          /* IP address of DHCP relay */
   unsigned char chaddr[MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
   char sname[MAX_DHCP_SNAME_LENGTH];    /* name of DHCP server */
   char file[MAX_DHCP_FILE_LENGTH];      /* boot file name (used for diskless booting?) */
   char options[MAX_DHCP_OPTIONS_LENGTH];  /* options */
};

#define IPV6_SHORT_LENGTH (INET6_ADDRSTRLEN - INET_ADDRSTRLEN)

DECLARE_PROTOCOL_HANDLER(DHCP, bool ipv4)
{
   DECLARE_PROTOCOL_HEADER(dhcphdr);

   uint8_t addressFamily = ipv4 ? AF_INET : AF_INET6;
   uint8_t ipLength = ipv4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
   
#define NTOP(FIELD, STR)\
if(!inet_ntop(addressFamily, &header->FIELD, STR, ipLength))\
{\
   perror("handleDHCP: inet_ntop error for " #STR);\
   return false;\
}

   char myIP[ipLength];
   NTOP(ciaddr, myIP)

   char offeredIP[ipLength];
   NTOP(yiaddr, offeredIP)

   char serverIP[ipLength];
   NTOP(siaddr, serverIP)

   char relayIP[ipLength];
   NTOP(giaddr, relayIP)

#undef NTOP

   if(!ipv4)
      ipLength = IPV6_SHORT_LENGTH;

   printf(
            "\t-> [DHCP] op: %u "
            "hardware address: [size: %u, type: %u] "
            "hops: %u xid: %x secs: %u flags: %x "
            "server name: %s, boot file: %s, options: %s\n"
            "\t\tIP: [mine: %*s, offered: %*s, server: %*s, relay: %*s]\n",
            header->op,
            header->hlen, header->htype,
            header->hops, ntohl(header->xid), ntohs(header->secs), ntohs(header->flags),
            header->sname, header->file, header->options,
            ipLength - 1, myIP,
            ipLength - 1, offeredIP,
            ipLength - 1, serverIP,
            ipLength - 1, relayIP);

   return true;
}

#define DEFINE_TEXT_PROTOCOL_HANDLER(PROTOCOL)\
DECLARE_PROTOCOL_HANDLER(PROTOCOL)\
{\
   printf(\
            "\t-> [" #PROTOCOL "]"\
            "\n%.*s\n", payload->length, payload->data);\
   \
   return true;\
}

DEFINE_TEXT_PROTOCOL_HANDLER(ECHO)
DEFINE_TEXT_PROTOCOL_HANDLER(TELNET)
DEFINE_TEXT_PROTOCOL_HANDLER(SMTP)
DEFINE_TEXT_PROTOCOL_HANDLER(HTTP)
DEFINE_TEXT_PROTOCOL_HANDLER(POP3)
DEFINE_TEXT_PROTOCOL_HANDLER(IMAP)

#define SRC_OR_DST_PORT(SRC, DST, PORT) ((SRC) == (PORT) || (DST) == (PORT))

#define HAS_PORT(PORT) SRC_OR_DST_PORT(sourcePort, destinationPort, PORT)

#define CONCAT(A, B) A##B
#define GET_PORT(PROTOCOL) CONCAT(PROTOCOL, _PORT)

#define HANDLE_PROTOCOL(PROTOCOL, ...) handle##PROTOCOL(payload, ##__VA_ARGS__)

// handles given protocol if its port number source or destination port
// ##__VA_ARGS__ - thanks to that the macro doesn't add a comma when there are no additional arguments
#define MAYBE_HANDLE(PROTOCOL, ...)\
if(HAS_PORT(GET_PORT(PROTOCOL)))\
   return HANDLE_PROTOCOL(PROTOCOL,  ##__VA_ARGS__)

// <linux/tcp.h>
DECLARE_PROTOCOL_HANDLER(TCP)
{
   DECLARE_PROTOCOL_HEADER(tcphdr);

   // Specifies the size of the TCP header in 32-bit words.
   // The minimum size header is 5 words and the maximum is 15 words thus giving the minimum size of 20 bytes
   // and maximum of 60 bytes, allowing for up to 40 bytes of options in the header.
   // This field gets its name from the fact that it is also the offset from the start of the TCP segment to the actual data.
   uint8_t headerLength = header->doff * sizeof(uint32_t);

   trimPayloadHeader(payload, headerLength);

   uint16_t sourcePort = ntohs(header->source);
   uint16_t destinationPort = ntohs(header->dest);

   printf(
            "\t-> [TCP] size: [header: %u, payload: %u], "
            "seq: %x "
            "ack seq: %x "
            "res1: %u "
            "fin: %u "
            "syn: %u "
            "rst: %u "
            "psh: %u "
            "ack: %u "
            "urg: %u "
            "ece: %u "
            "cwr: %u "
            "window: %u "
            "check: %x "
            "urg ptr: %u\n"
            "\t\tport: [src: %u, dst: %u]\n",
            headerLength,
            payload->length,
            ntohl(header->seq),
            ntohl(header->ack_seq),
            header->res1,
            header->fin,
            header->syn,
            header->rst,
            header->psh,
            header->ack,
            header->urg,
            header->ece,
            header->cwr,
            ntohs(header->window),
            ntohs(header->check),
            ntohs(header->urg_ptr),
            sourcePort, destinationPort);

   MAYBE_HANDLE(DNS);
   MAYBE_HANDLE(ECHO);
   MAYBE_HANDLE(HTTP);
   MAYBE_HANDLE(IMAP);
   MAYBE_HANDLE(POP3);
   MAYBE_HANDLE(SMTP);
   MAYBE_HANDLE(TELNET);

   return true;
}

// <linux/udp.h>
DECLARE_PROTOCOL_HANDLER(UDP, bool ipv4)
{
   DECLARE_PROTOCOL_HEADER(udphdr);

   uint16_t headerLength = sizeof *header;

   trimPayloadHeaderWithNewLength(payload, headerLength, ntohs(header->len) - headerLength);

   uint16_t sourcePort = ntohs(header->source);
   uint16_t destinationPort = ntohs(header->dest);

   printf(
            "\t-> [UDP] size: [header: %u, payload: %u], "
            "check: %x\n"
            "\t\tport: [src: %u, dst: %u]\n",
            headerLength,
            payload->length,
            ntohs(header->check),
            sourcePort,
            destinationPort);

   MAYBE_HANDLE(DHCP, ipv4);
   MAYBE_HANDLE(DNS);
   MAYBE_HANDLE(ECHO);
   
   return true;
}

DECLARE_PROTOCOL_HANDLER(TransportLayerProtocol, uint8_t protocol, bool ipv4)
{
   switch(protocol)
   {
      // <linux/in.h>
      case IPPROTO_UDP: return HANDLE_PROTOCOL(UDP, ipv4);
      case IPPROTO_TCP: return HANDLE_PROTOCOL(TCP);
   }
   
   return true;
}

// <linux/if_arp.h>
DECLARE_PROTOCOL_HANDLER(ARP)
{
   DECLARE_PROTOCOL_HEADER(arphdr);

   const uint8_t* address = (uint8_t*)&header->ar_op + sizeof header->ar_op;

   uint16_t protocolFormat = ntohs(header->ar_pro);   

   bool ipv4 = protocolFormat == ETH_P_IP;

   uint8_t addressFamily = ipv4 ? AF_INET : AF_INET6;
   uint8_t ipLength = ipv4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;

#define NTOP(ADDRESS, STR)\
if(!inet_ntop(addressFamily, ADDRESS, STR, ipLength))\
{\
   perror("handleARP: inet_ntop error for " #STR);\
   return false;\
}

   char senderIP[ipLength];
   uint8_t hardwareAddressLength = header->ar_hln;
   NTOP(address += hardwareAddressLength, senderIP);

   char targetIP[ipLength];
   uint8_t protocolAddressLength = header->ar_pln;
   NTOP(address + protocolAddressLength + hardwareAddressLength, targetIP);

#undef NTOP

   if(!ipv4)
      ipLength = IPV6_SHORT_LENGTH;

   printf(
            "\t-> [ARP] hardware address: [format: %x, length: %u], "
            "protocol address: [format: %x, length: %u], "
            "op: %u\n"
            "\t\tIP: [sender: %*s, target: %*s]\n",
            ntohs(header->ar_hrd), hardwareAddressLength,
            protocolFormat, protocolAddressLength,
            ntohs(header->ar_op),
            ipLength - 1, senderIP,
            ipLength - 1, targetIP);
   
   return true;
}

// <linux/icmp.h>
DECLARE_PROTOCOL_HANDLER(ICMP)
{
   DECLARE_PROTOCOL_HEADER(icmphdr);
   
   printf(
            "\t-> [ICMP] type: %u, code: %u, checksum: %x\n"
            "\t\techo: [id: %u, sequence: %u]\n",
            header->type, header->code, ntohs(header->checksum), ntohs(header->un.echo.id), ntohs(header->un.echo.sequence));
   
   return true;
}

// <linux/ip.h>
DECLARE_PROTOCOL_HANDLER(IPv4)
{
   DECLARE_PROTOCOL_HEADER(iphdr);

// man 3 inet_ntop:
// convert IPv4 and IPv6 addresses from binary to text form
#define NTOP(FIELD, STR)\
if(!inet_ntop(AF_INET, &header->FIELD, STR, sizeof STR))\
{\
   perror("handleIPv4: inet_ntop error for " #FIELD);\
   return false;\
}

   // 16 bytes
   char sourceIP[INET_ADDRSTRLEN];
   NTOP(saddr, sourceIP)

   char destinationIP[INET_ADDRSTRLEN];
   NTOP(daddr, destinationIP)

#undef NTOP

   // The IPv4 header is variable in size due to the optional 14th field (options).
   // The IHL field contains the size of the IPv4 header; it has 4 bits that specify the number of 32-bit words in the header. 
   uint8_t headerLength = header->ihl * sizeof(uint32_t);
   
   trimPayloadHeaderWithNewLength(payload, headerLength, ntohs(header->tot_len) - headerLength);

   uint8_t protocol = header->protocol;

   printf(
            "\t-> [IPv4] size: [header: %u, payload: %u], "
            "Version: %u "
            "ToS: %u "
            "ID: %x "
            "Fragment offset: %u "
            "TTL: %u "
            "Protocol: %u "
            "Checksum: %x\n"
            "\t\tIP: [src: %*s, dst: %*s]\n",
            headerLength, payload->length, header->version, header->tos,
            ntohs(header->id), ntohs(header->frag_off),
            header->ttl, protocol, ntohs(header->check),
            (int)sizeof sourceIP - 1, sourceIP,
            (int)sizeof destinationIP - 1, destinationIP);

   // <linux/in.h>
   if(protocol == IPPROTO_ICMP)
      return HANDLE_PROTOCOL(ICMP);

   return HANDLE_PROTOCOL(TransportLayerProtocol, protocol, true);
}

// <linux/ipv6.h>
DECLARE_PROTOCOL_HANDLER(IPv6)
{
   DECLARE_PROTOCOL_HEADER(ipv6hdr);

// man 3 inet_ntop:
// convert IPv4 and IPv6 addresses from binary to text form
#define NTOP(FIELD, STR)\
if(!inet_ntop(AF_INET6, &header->FIELD, STR, sizeof STR))\
{\
   perror("handleIPv6: inet_ntop error for " #FIELD);\
   return false;\
}

   // 46 bytes - can be in the "IPv6:IPv4" form
   char sourceIP[INET6_ADDRSTRLEN];
   NTOP(saddr, sourceIP)

   char destinationIP[INET6_ADDRSTRLEN];
   NTOP(daddr, destinationIP)

#undef NTOP

   uint16_t headerLength = sizeof *header;

   trimPayloadHeaderWithNewLength(payload, headerLength, ntohs(header->payload_len));

   printf(
            "\t-> [IPv6] size: [header: %u, payload: %u], "
            "Priority: %u "
            "Version: %u "
            "Flow label: %x.%x.%x "
            "Next header: %u "
            "Hop limit: %u \n"
            "\t\tIP: [src: %*s, dst: %*s]\n",
            headerLength, payload->length,
            header->priority, header->version,
            header->flow_lbl[0], header->flow_lbl[1], header->flow_lbl[2],
            header->nexthdr, header->hop_limit,
            IPV6_SHORT_LENGTH - 1, sourceIP,
            IPV6_SHORT_LENGTH - 1, destinationIP);
   
   return HANDLE_PROTOCOL(TransportLayerProtocol, header->nexthdr, false);
}

bool formatMAC(const uint8_t* mac, char* buffer, size_t bufferSize)
{
   if(snprintf(buffer, bufferSize, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]) < 0)
   {
      perror("formatMAC: snprintf error");

      return false;
   }

   return true;
}

// 6 numbers in hex (12 chars) + 5 colons + '\0'
#define MAC_STRING_LENGTH (ETHER_ADDR_LEN * 3)

// <net/ethernet.h>
DECLARE_PROTOCOL_HANDLER(Ethernet)
{
   DECLARE_PROTOCOL_HEADER(ether_header);

#define FORMAT_MAC(FIELD, BUFFER)\
if(!formatMAC(header->FIELD, BUFFER, sizeof BUFFER))\
return false

   char sourceMAC[MAC_STRING_LENGTH];
   FORMAT_MAC(ether_shost, sourceMAC);

   char destinationMAC[MAC_STRING_LENGTH];
   FORMAT_MAC(ether_dhost, destinationMAC);

#undef FORMAT_MAC

   uint16_t headerLength = sizeof *header;

   trimPayloadHeader(payload, headerLength);
   
   uint16_t etherType = ntohs(header->ether_type);

   printf(
            "[Ethernet] size: [header: %u, payload: %u], "
            "ether type: %x\n"
            "\t\tMAC: [src: %*s, dst: %*s]\n", headerLength, payload->length, etherType, (int)sizeof sourceMAC - 1, sourceMAC, (int)sizeof destinationMAC - 1, destinationMAC);

   switch(etherType)
   {
      case ETH_P_ARP: return HANDLE_PROTOCOL(ARP);
      case ETH_P_IP: return HANDLE_PROTOCOL(IPv4);
      case ETH_P_IPV6: return HANDLE_PROTOCOL(IPv6);
   }

   return true;
}

bool receiveData(int packetSocket, uint8_t* frame, uint16_t frameSize)
{
   ssize_t receivedCount = recv(packetSocket, frame, frameSize, 0);

   if(receivedCount == -1)
   {
      perror("receiveData: recv error");

      return false;
   }

   Payload payload = {.data = frame, .length = receivedCount};

   return handleEthernet(&payload);
}

bool sniff(int packetSocket)
{
   puts("-> Listening...\n");

   // size has to be big enough to fit large packets (e.g. HTTP)
   uint8_t frame[65535];
   
   while(1)
   {
      if(!receiveData(packetSocket, frame, sizeof frame))
         return false;

      // separating subsequent packets
      puts("____________________________________________________________________________________________________");
   }

   return true;
}

int handleCommandLineArguments(int argc, char* argv[])
{
   if(argc < 2)
   {
      printf("Usage: %s <network interface name>\n", argv[0]);

      return -1;
   }

   return getPacketSocket(argv[1]);
}

#define STR(X) #X
#define STR_HELPER(X) STR(X)

#define APP_PROTO_STR(PROTOCOL) "         -> " #PROTOCOL " (" STR_HELPER(GET_PORT(PROTOCOL)) ")\n"

void printHandledProtocolsInformation()
{
   puts(
         "-> Handled protocols (15):\n"
         "   -> Ethernet\n"
         "     -> ARP\n"
         "     -> IPv4 i IPv6\n"
         "       -> ICMP\n"
         "       -> TCP\n" 
         APP_PROTO_STR(DNS)
         APP_PROTO_STR(ECHO)
         APP_PROTO_STR(HTTP)
         APP_PROTO_STR(IMAP)
         APP_PROTO_STR(POP3)
         APP_PROTO_STR(SMTP)
         APP_PROTO_STR(TELNET)
         "       -> UDP\n"
         APP_PROTO_STR(DHCP)
         APP_PROTO_STR(DNS)
         APP_PROTO_STR(ECHO));
}

int main(int argc, char* argv[])
{
   int packetSocket = handleCommandLineArguments(argc, argv);

   if(packetSocket == -1)
      return 1;
   
   printHandledProtocolsInformation();

   bool success = sniff(packetSocket);

   close(packetSocket);
   
   return success ? 0 : 2;
}
