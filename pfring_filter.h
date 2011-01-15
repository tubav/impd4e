/* impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 *
 * Copyright (c) 2010, Robert Wuttke <flash@jpod.cc>
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your 
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* list all ip protocol numbers as assigned by the iana
 * see: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 */
/*
#define HOPOPT 
#define ICMP 
#define IGMP 
#define GGP 
#define IPv4 
#define ST 
#define TCP 
#define CBT 
#define EGP 
#define IGP 
#define BBN-RCC-MON 
#define NVP-II 
#define PUP 
#define ARGUS
#define EMCON
#define XNET
#define CHAOS
#define UDP
#define MUX
#define DCN-MEAS
#define HMP
#define PRM
#define XNS-IDP
#define TRUNK-1
#define TRUNK-2
#define LEAF-1
#define LEAF-2
#define RDP
#define IRTP
#define ISO-TP4
#define NETBLT
#define MFE-NSP
#define MERIT-INP
#define DCCP
#define 3PC
#define IDPR
#define XTP
#define DDP
#define IDPR-CMTP
#define TP++
#define IL
#define IPv6
#define SDRP
#define IPv6-Route
#define IPv6-Frag
#define IDRP
#define RSVP
#define GRE
#define DSR
#define BNA
#define ESP
#define AH
#define I-NLSP
#define SWIPE
#define NARP
#define MOBILE
#define TLSP
#define SKIP
#define IPv6-ICMP
#define IPv6-NoNxt
#define IPv6-Opts
#define ANYHOST
#define CFTP
#define ANYNET
#define SAT-EXPAK
#define KRYPTOLAN
#define RVD
#define IPPC
#define ANYDISTFS
#define SAT-MON
#define VISA
#define IPCV
#define CPNX
#define CPHB
#define WSN
#define PVP
#define BR-SAT-MON
#define SUN-ND
#define WB-MON
#define WB-EXPAK
#define ISO-IP
#define VMTP
#define SECURE-VMTP
#define VINES
#define TTP
#define NSFNET-IGP
#define DGP
#define TCF
#define EIGRP
#define OSPFIGP
#define Sprite-RPC
#define LARP
#define MTP
#define AX.25
#define IPIP
#define MICP
#define SCC-SP
#define ETHERIP
#define ENCAP
#define ANYPRIVENC
#define GMTP
#define IFMP
#define PNNI
#define PIM
#define ARIS
#define SCPS
#define QNX
#define A/N
#define IPComp
#define SNP
#define Compaq-Peer
#define IPX-in-IP
#define VRRP
#define PGM
#define ANY0HOP
#define L2TP
#define DDX
#define IATP
#define STP
#define SRP
#define UTI
#define SMP
#define SM
#define PTP
#define ISIS over IPv4
#define FIRE
#define CRTP
#define CRUDP
#define SSCOPMCE
#define IPLT
#define SPS
#define PIPESCTP
#define FC
#define RSVP-E2E-IGNORE
#define Mobility Header
#define UDPLite
#define MPLS-in-IP
#define manet
#define HIP
#define Shim6
#define WESP
#define ROHC
#define EXPTEST0
#define EXPTEST1
#define UNKNOWN_PROT 0xFF
*/

/* converts a string describing an ip protocol to the corresponding 
 * protocol number as assinged by the iana
 * see: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 * returns protocol number as assinged by the iana if found
 * returns 0xff if not found (0xff is marked as reserved by iana)
 */
uint8_t get_ip_prot( const char* prot );

void print_ip_prot( const char* prot );
void print_all_ip_prot();
void print_all_ip_prot_str();
