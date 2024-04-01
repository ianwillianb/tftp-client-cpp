/*
 * TFTPUtils.cpp
 *
 *  Created on: 27 de mar. de 2024
 *      Author: ianwillianb
 */

#include "TFTPUtils.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdio>
#include <cstring>

using TFTP::TFTPUtils;

std::pair<bool, sockaddr_in> TFTPUtils::ResolveNetworkIPV4Address(const std::string& address)
{
    addrinfo hints{};
    addrinfo* resolved_addr{nullptr};
    /*
     * Hints provides some criteria to the address resolution.
     * ai_family: AF_INET -> IPV4
     * ai_socktype: SOCK_DGRAM -> UDP
     * ai_protocol: 0 -> Automatic protocol selection
     * */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;

    const int rc = getaddrinfo(address.c_str(), NULL, &hints, &resolved_addr);

    if(rc != 0)
    {
        printf("[%s] Failed to resolve network address %s: %s.\n", __func__, address.c_str(),
        		gai_strerror(rc));
        return {};
    }

	sockaddr_in resolved_ipv4_addr{};
	bool addr_resolution_status{};

    //Iterate over results provided by getaddrinfo()
    for (addrinfo* p = resolved_addr; p != nullptr; p = p->ai_next)
    {
          // Resolved IPV4 address
          if(p->ai_family == AF_INET)
          {
              memcpy(&resolved_ipv4_addr, p->ai_addr, sizeof(sockaddr_in));
              addr_resolution_status = true;
              char ipstr[INET_ADDRSTRLEN]{0};
              inet_ntop(AF_INET, (void*) (&resolved_ipv4_addr.sin_addr), ipstr, sizeof(ipstr));
              printf("%s: Resolved host address %s to IP V4 address: %s\n", __func__, address.c_str(), ipstr);
              break;
          }
          else
          {
        	  // Do nothing, only resolving address to IPV4
          }
      }

    freeaddrinfo(resolved_addr);

    return {addr_resolution_status, resolved_ipv4_addr};
}
