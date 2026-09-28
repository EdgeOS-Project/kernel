/* SPDX-License-Identifier: MPL-2.0 */
/* Validate the Linux-visible records returned by libc getifaddrs(). */

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int main(void) {
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *entry;
    int eth0_ipv4 = 0;
    int eth0_running = 0;

    if (getifaddrs(&addresses) < 0) {
        perror("getifaddrs");
        return 1;
    }
    for (entry = addresses; entry; entry = entry->ifa_next) {
        char text[INET6_ADDRSTRLEN] = "-";
        int family = entry->ifa_addr ? entry->ifa_addr->sa_family : AF_UNSPEC;

        if (family == AF_INET) {
            const struct sockaddr_in *address =
                (const struct sockaddr_in *)entry->ifa_addr;
            (void)inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text));
        } else if (family == AF_INET6) {
            const struct sockaddr_in6 *address =
                (const struct sockaddr_in6 *)entry->ifa_addr;
            (void)inet_ntop(AF_INET6, &address->sin6_addr, text, sizeof(text));
        }
        printf("name=%s family=%d flags=0x%x address=%s\n",
               entry->ifa_name ? entry->ifa_name : "-", family,
               entry->ifa_flags, text);
        if (entry->ifa_name && !strcmp(entry->ifa_name, "eth0")) {
            if (entry->ifa_flags & IFF_RUNNING) eth0_running = 1;
            if (family == AF_INET &&
                ntohl(((const struct sockaddr_in *)entry->ifa_addr)->sin_addr.s_addr) !=
                    INADDR_LOOPBACK)
                eth0_ipv4 = 1;
        }
    }
    freeifaddrs(addresses);
    if (!eth0_ipv4 || !eth0_running) {
        fprintf(stderr, "GETIFADDRS_SEMANTICS_FAIL ipv4=%d running=%d\n",
                eth0_ipv4, eth0_running);
        return 1;
    }
    puts("GETIFADDRS_SEMANTICS_PASS");
    return 0;
}
