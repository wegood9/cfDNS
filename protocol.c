#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "protocol.h"

static const struct {
  unsigned int type;
  const char * const name;
} typestr[] = {
  { 1,   "A" }, /* a host address [RFC1035] */
  { 2,   "NS" }, /* an authoritative name server [RFC1035] */
  { 3,   "MD" }, /* a mail destination (OBSOLETE - use MX) [RFC1035] */
  { 4,   "MF" }, /* a mail forwarder (OBSOLETE - use MX) [RFC1035] */
  { 5,   "CNAME" }, /* the canonical name for an alias [RFC1035] */
  { 6,   "SOA" }, /* marks the start of a zone of authority [RFC1035] */
  { 7,   "MB" }, /* a mailbox domain name (EXPERIMENTAL) [RFC1035] */
  { 8,   "MG" }, /* a mail group member (EXPERIMENTAL) [RFC1035] */
  { 9,   "MR" }, /* a mail rename domain name (EXPERIMENTAL) [RFC1035] */
  { 10,  "NULL" }, /* a null RR (EXPERIMENTAL) [RFC1035] */
  { 11,  "WKS" }, /* a well known service description [RFC1035] */
  { 12,  "PTR" }, /* a domain name pointer [RFC1035] */
  { 13,  "HINFO" }, /* host information [RFC1035] */
  { 14,  "MINFO" }, /* mailbox or mail list information [RFC1035] */
  { 15,  "MX" }, /* mail exchange [RFC1035] */
  { 16,  "TXT" }, /* text strings [RFC1035] */
  { 17,  "RP" }, /* for Responsible Person [RFC1183] */
  { 18,  "AFSDB" }, /* for AFS Data Base location [RFC1183][RFC5864] */
  { 19,  "X25" }, /* for X.25 PSDN address [RFC1183] */
  { 20,  "ISDN" }, /* for ISDN address [RFC1183] */
  { 21,  "RT" }, /* for Route Through [RFC1183] */
  { 22,  "NSAP" }, /* for NSAP address, NSAP style A record [RFC1706] */
  { 23,  "NSAP_PTR" }, /* for domain name pointer, NSAP style [RFC1348][RFC1637][RFC1706] */
  { 24,  "SIG" }, /* for security signature [RFC2535][RFC2536][RFC2537][RFC2931][RFC3008][RFC3110][RFC3755][RFC4034] */
  { 25,  "KEY" }, /* for security key [RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110][RFC3755][RFC4034] */
  { 26,  "PX" }, /* X.400 mail mapping information [RFC2163] */
  { 27,  "GPOS" }, /* Geographical Position [RFC1712] */
  { 28,  "AAAA" }, /* IP6 Address [RFC3596] */
  { 29,  "LOC" }, /* Location Information [RFC1876] */
  { 30,  "NXT" }, /* Next Domain (OBSOLETE) [RFC2535][RFC3755] */
  { 31,  "EID" }, /* Endpoint Identifier [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt] 1995-06*/
  { 32,  "NIMLOC" }, /* Nimrod Locator [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt] 1995-06*/
  { 33,  "SRV" }, /* Server Selection [1][RFC2782] */
  { 34,  "ATMA" }, /* ATM Address [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.] */
  { 35,  "NAPTR" }, /* Naming Authority Pointer [RFC2168][RFC2915][RFC3403] */
  { 36,  "KX" }, /* Key Exchanger [RFC2230] */
  { 37,  "CERT" }, /* CERT [RFC4398] */
  { 38,  "A6" }, /* A6 (OBSOLETE - use AAAA) [RFC2874][RFC3226][RFC6563] */
  { 39,  "DNAME" }, /* DNAME [RFC6672] */
  { 40,  "SINK" }, /* SINK [Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink] 1997-11*/
  { 41,  "OPT" }, /* OPT [RFC3225][RFC6891] */
  { 42,  "APL" }, /* APL [RFC3123] */
  { 43,  "DS" }, /* Delegation Signer [RFC3658][RFC4034] */
  { 44,  "SSHFP" }, /* SSH Key Fingerprint [RFC4255] */
  { 45,  "IPSECKEY" }, /* IPSECKEY [RFC4025] */
  { 46,  "RRSIG" }, /* RRSIG [RFC3755][RFC4034] */
  { 47,  "NSEC" }, /* NSEC [RFC3755][RFC4034][RFC9077] */
  { 48,  "DNSKEY" }, /* DNSKEY [RFC3755][RFC4034] */
  { 49,  "DHCID" }, /* DHCID [RFC4701] */
  { 50,  "NSEC3" }, /* NSEC3 [RFC5155][RFC9077] */
  { 51,  "NSEC3PARAM" }, /* NSEC3PARAM [RFC5155] */
  { 52,  "TLSA" }, /* TLSA [RFC6698] */
  { 53,  "SMIMEA" }, /* S/MIME cert association [RFC8162] SMIMEA/smimea-completed-template 2015-12-01*/
  { 55,  "HIP" }, /* Host Identity Protocol [RFC8005] */
  { 56,  "NINFO" }, /* NINFO [Jim_Reid] NINFO/ninfo-completed-template 2008-01-21*/
  { 57,  "RKEY" }, /* RKEY [Jim_Reid] RKEY/rkey-completed-template 2008-01-21*/
  { 58,  "TALINK" }, /* Trust Anchor LINK [Wouter_Wijngaards] TALINK/talink-completed-template 2010-02-17*/
  { 59,  "CDS" }, /* Child DS [RFC7344] CDS/cds-completed-template 2011-06-06*/
  { 60,  "CDNSKEY" }, /* DNSKEY(s) the Child wants reflected in DS [RFC7344] 2014-06-16*/
  { 61,  "OPENPGPKEY" }, /* OpenPGP Key [RFC7929] OPENPGPKEY/openpgpkey-completed-template 2014-08-12*/
  { 62,  "CSYNC" }, /* Child-To-Parent Synchronization [RFC7477] 2015-01-27*/
  { 63,  "ZONEMD" }, /* Message Digest Over Zone Data [RFC8976] ZONEMD/zonemd-completed-template 2018-12-12*/
  { 64,  "SVCB" }, /* Service Binding [draft-ietf-dnsop-svcb-https-00] SVCB/svcb-completed-template 2020-06-30*/
  { 65,  "HTTPS" }, /* HTTPS Binding [draft-ietf-dnsop-svcb-https-00] HTTPS/https-completed-template 2020-06-30*/
  { 99,  "SPF" }, /* [RFC7208] */
  { 100, "UINFO" }, /* [IANA-Reserved] */
  { 101, "UID" }, /* [IANA-Reserved] */
  { 102, "GID" }, /* [IANA-Reserved] */
  { 103, "UNSPEC" }, /* [IANA-Reserved] */
  { 104, "NID" }, /* [RFC6742] ILNP/nid-completed-template */
  { 105, "L32" }, /* [RFC6742] ILNP/l32-completed-template */
  { 106, "L64" }, /* [RFC6742] ILNP/l64-completed-template */
  { 107, "LP" }, /* [RFC6742] ILNP/lp-completed-template */
  { 108, "EUI48" }, /* an EUI-48 address [RFC7043] EUI48/eui48-completed-template 2013-03-27*/
  { 109, "EUI64" }, /* an EUI-64 address [RFC7043] EUI64/eui64-completed-template 2013-03-27*/
  { 249, "TKEY" }, /* Transaction Key [RFC2930] */
  { 250, "TSIG" }, /* Transaction Signature [RFC8945] */
  { 251, "IXFR" }, /* incremental transfer [RFC1995] */
  { 252, "AXFR" }, /* transfer of an entire zone [RFC1035][RFC5936] */
  { 253, "MAILB" }, /* mailbox-related RRs (MB, MG or MR) [RFC1035] */
  { 254, "MAILA" }, /* mail agent RRs (OBSOLETE - see MX) [RFC1035] */
  { 255, "ANY" }, /* A request for some or all records the server has available [RFC1035][RFC6895][RFC8482] */
  { 256, "URI" }, /* URI [RFC7553] URI/uri-completed-template 2011-02-22*/
  { 257, "CAA" }, /* Certification Authority Restriction [RFC8659] CAA/caa-completed-template 2011-04-07*/
  { 258, "AVC" }, /* Application Visibility and Control [Wolfgang_Riedel] AVC/avc-completed-template 2016-02-26*/
  { 259, "DOA" }, /* Digital Object Architecture [draft-durand-doa-over-dns] DOA/doa-completed-template 2017-08-30*/
  { 260, "AMTRELAY" }, /* Automatic Multicast Tunneling Relay [RFC8777] AMTRELAY/amtrelay-completed-template 2019-02-06*/
  { 32768,  "TA" }, /* DNSSEC Trust Authorities [Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.] 2005-12-13*/
  { 32769,  "DLV" }, /* DNSSEC Lookaside Validation (OBSOLETE) [RFC8749][RFC4431] */
};

bool cidr_match(const struct in_addr *addr, const struct in_addr *net, uint8_t bits) {
    if (bits == 0)
    // C99 6.5.7 (3): u32 << 32 is undefined behaviour
        return true;
    return !((addr->s_addr ^ net->s_addr) & htonl(0xFFFFFFFFu << (32 - bits)));
}

bool cidr6_match(const struct in6_addr *address, const struct in6_addr *network, uint8_t bits) {
#ifdef __linux__
    const uint32_t *a = address->s6_addr32;
    const uint32_t *n = network->s6_addr32;
#else
    const uint32_t *a = address->__u6_addr.__u6_addr32;
    const uint32_t *n = network->__u6_addr.__u6_addr32;
#endif
    int bits_whole, bits_incomplete;
    bits_whole = bits >> 5;                 // number of whole u32
    bits_incomplete = bits & 0x1F;    // number of bits in incomplete u32
    if (bits_whole) {
        if (memcmp(a, n, bits_whole << 2)) {
            return false;
        }
    }
    if (bits_incomplete) {
        uint32_t mask = htonl((0xFFFFFFFFu) << (32 - bits_incomplete));
        if ((a[bits_whole] ^ n[bits_whole]) & mask) {
            return false;
        }
    }
    return true;
}

bool isValidIPv6(const char *ip)
{
    struct sockaddr_in6 addr;

    if (!ip || inet_pton(AF_INET6, ip, &addr.sin6_addr) != 1)
                return false;
        else
            return true;
}

bool isValidIPv4(const char *ip)
{
    struct sockaddr_in addr;
    
    if (!ip || inet_pton(AF_INET, ip, &addr.sin_addr) != 1)
                return false;
        else
            return true;
}

int ParseDomainName(char *packet_index, char *packet_start, int packet_size, char *dest_buffer) {

    int bytes_read = 0;
    uint8_t label_length;
    uint16_t offset;
    char *packet_end = packet_start + packet_size;

        /* The domain name is stored as a series of sub-domains or pointers to
         sub-domains. Each sub-domain contains the length as the first byte, 
         followed by LENGTH number of bytes (no null-terminator). If it's a pointer,
         the first two bits of the length byte will be set, and then the rest of
         the bits contain an offset from the start of the packet to another
         sub-domain (or set of sub-domains). 
         We first get the length of the sub-domain (or label), check if it's a
         pointer, and if not, read the that number of bytes into a buffer. Each
         sub-domain is separated by a period character. If a pointer is found,
         we can call this function recursively. 
         The end of the domain name is found when we read a label length of 
         0 bytes. */

    if (packet_index >= packet_end)
        return -1;

    label_length = (uint8_t)*packet_index;

    while (label_length != 0) {
        /* If this isn't the first label, add a period in between
             the labels. */
        if (bytes_read > 0)
            *dest_buffer++ = '.';

        /* Check to see if this label is a pointer. */
        if ((label_length & DNS_POINTER_FLAG) == DNS_POINTER_FLAG) {
            char *new_packet_index;

            offset = ntohs(*(uint16_t *)packet_index) & DNS_POINTER_OFFSET_MASK;
            new_packet_index = packet_start + offset;
            if (new_packet_index >= packet_end)
                return -1;

            /* Recursively call this function with the packet index set to
     the offset value and the current location of the destination
     buffer. Since we're using an offset and reading from some
     other part of memory, we only need to increment the number
     of bytes read by 2 (for the pointer value). */
            ParseDomainName(new_packet_index, packet_start, packet_size, dest_buffer);
            return bytes_read + 2;
        }
        packet_index++;
        label_length &= DNS_LABEL_LENGTH_MASK;

        if (packet_index + label_length >= packet_end)
            return -1;

        memcpy(dest_buffer, packet_index, label_length);
        dest_buffer += label_length;
        *dest_buffer = 0;

        packet_index += label_length;
        bytes_read += label_length + 1;

        label_length = (uint8_t)*packet_index;
    }

    bytes_read++; //.

    return bytes_read;
}

//移动指针并检查是否越界
bool inc(char **buffer_p, char *packet_end, int bytes) {
    *buffer_p += bytes;
    return *buffer_p >= packet_end ? 0 : 1;
}

char *LookupType(const int type) {
    for (int i = 0; i < 89; i++)
        if (type == typestr[i].type)
            return typestr[i].name;
    return "Unknown";
}

