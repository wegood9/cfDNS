#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>

#include "protocol.h"

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

bool is_valid_ipv6(const char *ip)
{
    struct sockaddr_in6 addr;
    if (!ip || inet_pton(AF_INET6, ip, &addr.sin6_addr) != 1)
                return false;
        else
            return true;
}

bool is_valid_ipv4(const char *ip)
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