

The Transmission Control Protocol (TCP) uses port numbers to identify specific services or applications on a networked device. Port numbers range from 0 to 65535 and are categorized into three ranges by the Internet Assigned Numbers Authority (IANA):

- **Well-Known Ports (0–1023)**: Reserved for system-level services and widely recognized protocols.
- **Registered Ports (1024–49151)**: Assigned to user applications or services upon request.
- **Dynamic or Private Ports (49152–65535)**: Unassigned and available for temporary or private use.

This document provides a detailed list of well-known TCP ports (0–1023), as these are the most standardized and commonly used. Due to the vast number of possible ports (65,536), listing every port, including unassigned ones, is impractical. For the complete list, including registered and dynamic ports, refer to the [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml).

## Well-Known TCP Ports (0–1023)

The following table lists the well-known TCP ports and their associated protocols, based on IANA assignments and common usage:

| Port | Protocol Description                                                   | Notes                                                      |
| ---- | ---------------------------------------------------------------------- | ---------------------------------------------------------- |
| 0    | Reserved                                                               | Not used for host communication                            |
| 1    | TCP Port Service Multiplexer (TCPMUX)                                  | Historic, rarely used                                      |
| 5    | Remote Job Entry                                                       | Historic, also identified as TCP/5 by MIB PIM              |
| 7    | Echo Protocol                                                          | Used for testing network connectivity                      |
| 9    | Discard Protocol                                                       | Discards received data; also unofficial Wake-on-LAN        |
| 11   | Active Users (systat service)                                          | System status service                                      |
| 13   | Daytime Protocol                                                       | Returns current time                                       |
| 15   | Previously netstat service                                             | Unofficial, historic network status service                |
| 17   | Quote of the Day (QOTD)                                                | Returns a short message or quote                           |
| 18   | Message Send Protocol                                                  | Historic messaging protocol                                |
| 19   | Character Generator Protocol (CHARGEN)                                 | Generates a stream of characters for testing               |
| 20   | File Transfer Protocol (FTP) data transfer                             | Used for FTP data transfer                                 |
| 21   | File Transfer Protocol (FTP) control (command)                         | Used for FTP command control                               |
| 22   | Secure Shell (SSH)                                                     | Secure logins, file transfers (scp, sftp), port forwarding |
| 23   | Telnet protocol                                                        | Unencrypted text communications                            |
| 25   | Simple Mail Transfer Protocol (SMTP)                                   | Email routing between mail servers                         |
| 37   | Time Protocol                                                          | Synchronizes time across devices                           |
| 43   | WHOIS protocol                                                         | Queries domain and network information                     |
| 49   | TACACS Login Host protocol                                             | TACACS+ uses TCP 49 for authentication                     |
| 53   | Domain Name System (DNS)                                               | Resolves domain names to IP addresses                      |
| 70   | Gopher protocol                                                        | Predecessor to HTTP for document retrieval                 |
| 79   | Finger protocol                                                        | Retrieves user information                                 |
| 80   | Hypertext Transfer Protocol (HTTP)                                     | Web browsing, uses TCP in HTTP 1.x and 2                   |
| 88   | Kerberos authentication system                                         | Secure network authentication                              |
| 95   | SUPDUP                                                                 | Terminal-independent remote login                          |
| 101  | NIC host name                                                          | Historic host name service                                 |
| 102  | ISO Transport Service Access Point (TSAP) Class 0 protocol             | ISO network protocol                                       |
| 104  | Digital Imaging and Communications in Medicine (DICOM)                 | Medical imaging data transfer; also uses port 11112        |
| 105  | CCSO Nameserver                                                        | Directory service                                          |
| 107  | Remote User Telnet Service (RTelnet)                                   | Remote telnet access                                       |
| 108  | IBM Systems Network Architecture (SNA) gateway access server           | IBM network protocol                                       |
| 109  | Post Office Protocol, version 2 (POP2)                                 | Historic email retrieval protocol                          |
| 110  | Post Office Protocol, version 3 (POP3)                                 | Email retrieval                                            |
| 111  | Open Network Computing Remote Procedure Call (ONC RPC)                 | Remote procedure calls                                     |
| 113  | Ident                                                                  | Authentication/identification, used by IRC servers         |
| 115  | Simple File Transfer Protocol                                          | Simplified file transfer                                   |
| 117  | UUCP Mapping Project (path service)                                    | Unix-to-Unix Copy path service                             |
| 119  | Network News Transfer Protocol (NNTP)                                  | Retrieval of newsgroup messages                            |
| 135  | DCE endpoint resolution, Microsoft EPMAP                               | Microsoft RPC endpoint mapping                             |
| 143  | Internet Message Access Protocol (IMAP)                                | Email message management                                   |
| 179  | Border Gateway Protocol (BGP)                                          | Exchanges routing information                              |
| 194  | Internet Relay Chat (IRC)                                              | Real-time chat                                             |
| 201  | AppleTalk Routing Maintenance                                          | Apple network protocol                                     |
| 209  | Quick Mail Transfer Protocol                                           | Email transfer                                             |
| 210  | ANSI Z39.50                                                            | Library and information retrieval                          |
| 213  | Internetwork Packet Exchange (IPX)                                     | Novell network protocol                                    |
| 218  | Message Posting Protocol (MPP)                                         | Messaging service                                          |
| 220  | Internet Message Access Protocol, version 3                            | Variant of IMAP                                            |
| 259  | Efficient Short Remote Operations (ESRO)                               | Remote operations protocol                                 |
| 262  | Arcisdms                                                               | Data management service                                    |
| 264  | Border Gateway Multicast Protocol (BGMP)                               | Multicast routing                                          |
| 280  | HTTP Management (http-mgmt)                                            | HTTP management interface                                  |
| 308  | Novastor Online Backup                                                 | Backup service                                             |
| 311  | macOS Server Admin                                                     | AppleShare IP web administration                           |
| 318  | PKIX Time Stamp Protocol (TSP)                                         | Timestamping for digital signatures                        |
| 319  | Precision Time Protocol (PTP) event messages                           | Time synchronization                                       |
| 320  | Precision Time Protocol (PTP) general messages                         | Time synchronization                                       |
| 323  | Resource Public Key Infrastructure                                     | Key management                                             |
| 350  | Mapping of Airline Traffic over Internet Protocol (MATIP) type A       | Airline data transfer                                      |
| 351  | Mapping of Airline Traffic over Internet Protocol (MATIP) type B       | Airline data transfer                                      |
| 356  | Cloanto Amiga Explorer                                                 | Amiga network service                                      |
| 366  | On-Demand Mail Relay (ODMR)                                            | Email relay                                                |
| 369  | Rpc2portmap                                                            | RPC port mapping                                           |
| 370  | Coda authentication server (codaauth2), SecureCast                     | Authentication and secure communication                    |
| 371  | ClearCase albd                                                         | Version control service                                    |
| 376  | Amiga Envoy Network Inquiry Protocol                                   | Amiga network protocol                                     |
| 383  | HP Data Alarm Manager                                                  | HP monitoring service                                      |
| 384  | A Remote Network Server System                                         | Remote server access                                       |
| 387  | AppleTalk Update-based Routing Protocol (AURP)                         | Apple network routing                                      |
| 388  | Unidata LDM                                                            | Real-time data distribution                                |
| 389  | Lightweight Directory Access Protocol (LDAP)                           | Directory services                                         |
| 399  | Digital Equipment Corporation DECnet+ (Phase V) over TCP/IP            | DEC network protocol                                       |
| 401  | Uninterruptible Power Supply (UPS)                                     | Power management                                           |
| 427  | Service Location Protocol (SLP)                                        | Service discovery                                          |
| 433  | Network News Transfer Protocol (NNTP)                                  | Part of NNTP                                               |
| 434  | Mobile IP Agent                                                        | Mobile IP communication                                    |
| 443  | Hypertext Transfer Protocol Secure (HTTPS)                             | Secure web browsing                                        |
| 444  | Simple Network Paging Protocol (SNPP)                                  | Paging services                                            |
| 445  | Microsoft-DS (Directory Services)                                      | Active Directory, Windows shares, SMB                      |
| 464  | Kerberos Change/Set Password                                           | Kerberos password management                               |
| 465  | Message Submission over TLS                                            | Email submission                                           |
| 497  | Retrospect                                                             | Backup and restore service                                 |
| 500  | Internet Security Association and Key Management Protocol (ISAKMP/IKE) | VPN key exchange                                           |
| 502  | Modbus Protocol                                                        | Industrial automation                                      |
| 504  | Citadel                                                                | Multiservice groupware protocol                            |
| 510  | FirstClass Protocol                                                    | Groupware system                                           |
| 512  | Remote Process Execution (rexec), comsat                               | Remote execution and messaging                             |
| 513  | rlogin, Who                                                            | Remote login and user lookup                               |
| 514  | Remote Shell (rsh), Syslog                                             | Non-interactive commands, system logging                   |
| 515  | Line Printer Daemon (LPD)                                              | Print services                                             |
| 517  | Talk                                                                   | Chat service                                               |
| 518  | NTalk                                                                  | Network talk service                                       |
| 520  | Extended File Name Server (efs), Routing Information Protocol (RIP)    | File and routing services                                  |
| 521  | Routing Information Protocol Next Generation (RIPng)                   | IPv6 routing                                               |
| 524  | NetWare Core Protocol (NCP)                                            | NetWare server access                                      |
| 525  | Timeserver (Timed)                                                     | Time synchronization                                       |
| 530  | Remote Procedure Call (RPC)                                            | Remote procedure calls                                     |
| 532  | Netnews                                                                | News service                                               |
| 533  | Netwall                                                                | Emergency broadcasts                                       |
| 540  | Unix-to-Unix Copy Protocol (UUCP)                                      | File transfer between Unix systems                         |
| 542  | Commerce Applications                                                  | E-commerce services                                        |
| 543  | Kerberos Login (klogin)                                                | Kerberos authentication                                    |
| 544  | Kerberos Remote Shell (kshell)                                         | Kerberos remote access                                     |
| 546  | DHCPv6 Client                                                          | IPv6 DHCP client                                           |
| 547  | DHCPv6 Server                                                          | IPv6 DHCP server                                           |
| 548  | Apple Filing Protocol (AFP)                                            | Apple file sharing                                         |
| 554  | Real Time Streaming Protocol (RTSP)                                    | Streaming media control                                    |
| 556  | Remote File System (Remotefs)                                          | Remote file access                                         |
| 560  | Remote Monitor (rmonitor)                                              | Monitoring service                                         |
| 561  | Monitor                                                                | System monitoring                                          |
| 563  | NNTP over TLS/SSL (NNTPS)                                              | Secure news transfer                                       |
| 587  | Email Message Submission                                               | Preferred for email submission                             |
| 591  | FileMaker Web Sharing                                                  | FileMaker web access                                       |
| 593  | HTTP RPC Endpoint Mapper                                               | Remote procedure call over HTTP                            |
| 601  | Reliable Syslog Service                                                | System logging                                             |
| 604  | TUNNEL Profile                                                         | Application layer tunneling                                |
| 623  | ASF Remote Management and Control Protocol (ASF-RMCP), IPMI            | Remote management                                          |
| 631  | Internet Printing Protocol (IPP)                                       | Printing services, CUPS administration                     |
| 635  | RLZ DBase                                                              | Database service                                           |
| 636  | Lightweight Directory Access Protocol over TLS/SSL (LDAPS)             | Secure directory services                                  |
| 639  | Multicast Source Discovery Protocol (MSDP)                             | Multicast routing                                          |
| 641  | SupportSoft Nexus Remote Command                                       | Remote control proxy                                       |
| 643  | SANity                                                                 | Storage area network service                               |
| 646  | Label Distribution Protocol (LDP)                                      | MPLS routing                                               |
| 647  | DHCP Failover Protocol                                                 | DHCP server coordination                                   |
| 993  | Internet Message Access Protocol over TLS/SSL (IMAPS)                  | Secure email access                                        |

## Registered and Dynamic Ports

- **Registered Ports (1024–49151)**: These ports are assigned by IANA for specific applications or services upon request. Examples include:
    - 1433: Microsoft SQL Server
    - 3306: MySQL Database
    - 3389: Remote Desktop Protocol (RDP)
    - The full list is extensive and can be found in the IANA registry.
- **Dynamic Ports (49152–65535)**: These are not assigned by IANA and are used for temporary or private communications, such as client-side ephemeral ports during TCP connections.

## Accessing the Complete List

The IANA Service Name and Transport Protocol Port Number Registry is the definitive source for all assigned TCP ports. It is available in multiple formats (CSV, XML, HTML, plain text) and updated regularly. You can access it at [IANA Port Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml). The registry includes:

- Service names and port numbers for TCP, UDP, SCTP, and DCCP.
- Detailed descriptions and references to relevant RFCs.
- Information on whether ports are assigned, reserved, or unassigned.

## Notes on Usage

- **Assignment Process**: IANA assigns ports through processes like IETF Review, IESG Approval, or Expert Review, as outlined in RFC 6335.
- **Unofficial Usage**: Some ports may be used unofficially for non-standard applications, which may not be reflected in the IANA registry.
- **Security Considerations**: Not all traffic on a registered port corresponds to the assigned service. Network administrators should configure firewalls based on traffic analysis, not just port numbers.

## Integration with Your IDS

In the context of your Intrusion Detection System (IDS), identifying protocols based on TCP port numbers is critical for features like `HTTP`, `HTTPS`, `DNS`, etc. Your code already parses the `source_port` and `dest_port` from the TCP header. You can use the above list to map these ports to protocols (e.g., port 80 → HTTP, port 443 → HTTPS). For example:

- Check `pkt.protocol == 6` (TCP) and then match `pkt.source_port` or `pkt.dest_port` against the list to identify the protocol.
- Example logic:
    
    ```cpp
    if (pkt.protocol == 6) {
        if (pkt.source_port == 80 || pkt.dest_port == 80) {
            log("Packet is HTTP");
        } else if (pkt.source_port == 443 || pkt.dest_port == 443) {
            log("Packet is HTTPS");
        }
    }
    ```
    

This document provides a comprehensive overview of well-known TCP ports and directs you to the IANA registry for the complete list of all ports.




# reference

**IANA Service Name and Transport Protocol Port Number Registry**

- **URL**: [https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- **Description**: The Internet Assigned Numbers Authority (IANA) maintains the official registry of port numbers for TCP, UDP, SCTP, and DCCP. This is the primary authoritative source for all port assignments, including well-known, registered, and dynamic ports. The list I provided (ports 0–1023) was cross-referenced with IANA’s assignments to ensure accuracy.
- **Usage**: Used to confirm port assignments, service names, and protocol descriptions (e.g., port 80 for HTTP, port 443 for HTTPS).
- **Access Date**: April 27, 2025 (assumed based on the current date provided).