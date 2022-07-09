#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <net/if.h> 
#include <ifaddrs.h>
#include <netdb.h>

#include "socket.h"
#include "config.h"

bool isIPv6(char *ip_addr){
    if (ip_addr[0] == '[' || (!strrchr(ip_addr, ':') && strrchr(ip_addr, ':') != !strchr(ip_addr, ':')) )
        return true;
    else
        return false;
}

int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, unsigned int timeout_ms) {
    int rc = 0;
    // Set O_NONBLOCK
    int sockfd_flags_before;
    if((sockfd_flags_before=fcntl(sockfd,F_GETFL,0)<0)) return -1;
    if(fcntl(sockfd,F_SETFL,sockfd_flags_before | O_NONBLOCK)<0) return -1;
    // Start connecting (asynchronously)
    do {
        if (connect(sockfd, addr, addrlen)<0) {
            // Did connect return an error? If so, we'll fail.
            if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
                rc = -1;
            }
            // Otherwise, we'll wait for it to complete.
            else {
                // Set a deadline timestamp 'timeout' ms from now (needed b/c poll can be interrupted)
                struct timespec now;
                if(clock_gettime(CLOCK_MONOTONIC, &now)<0) { rc=-1; break; }
                struct timespec deadline = { .tv_sec = now.tv_sec,
                                             .tv_nsec = now.tv_nsec + timeout_ms*1000000l};
                // Wait for the connection to complete.
                do {
                    // Calculate how long until the deadline
                    if(clock_gettime(CLOCK_MONOTONIC, &now)<0) { rc=-1; break; }
                    int ms_until_deadline = (int)(  (deadline.tv_sec  - now.tv_sec)*1000l
                                                  + (deadline.tv_nsec - now.tv_nsec)/1000000l);
                    if(ms_until_deadline<0) { rc=0; break; }
                    // Wait for connect to complete (or for the timeout deadline)
                    struct pollfd pfds[] = { { .fd = sockfd, .events = POLLOUT } };
                    rc = poll(pfds, 1, ms_until_deadline);
                    // If poll 'succeeded', make sure it *really* succeeded
                    if(rc>0) {
                        int error = 0; socklen_t len = sizeof(error);
                        int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
                        if(retval==0) errno = error;
                        if(error!=0) rc=-1;
                    }
                }
                // If poll was interrupted, try again.
                while(rc==-1 && errno==EINTR);
                // Did poll timeout? If so, fail.
                if(rc==0) {
                    errno = ETIMEDOUT;
                    rc=-1;
                }
            }
        }
    } while(0);
    // Restore original O_NONBLOCK state
    if(fcntl(sockfd,F_SETFL,sockfd_flags_before)<0) return -1;
    // Success
    return rc;
}

unsigned GetScopeForIp(const char *ip){
    struct ifaddrs *addrs;
    char ipAddress[NI_MAXHOST];
    unsigned scope=0;
    // walk over the list of all interface addresses
    getifaddrs(&addrs);
    for(struct ifaddrs *addr=addrs;addr;addr=addr->ifa_next){
        if (addr->ifa_addr && addr->ifa_addr->sa_family==AF_INET6){ // only interested in ipv6 ones
            getnameinfo(addr->ifa_addr,sizeof(struct sockaddr_in6),ipAddress,sizeof(ipAddress),NULL,0,NI_NUMERICHOST);
            // result actually contains the interface name, so strip it
            for(int i=0;ipAddress[i];i++){
                if(ipAddress[i]=='%'){
                    ipAddress[i]='\0';
                    break;
                }
            }
            // if the ip matches, convert the interface name to a scope index
            if(strcmp(ipAddress,ip)==0){
                scope=if_nametoindex(addr->ifa_name);
                break;
            }
        }
    }
    freeifaddrs(addrs);
    return scope;
}