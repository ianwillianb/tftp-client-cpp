/*
 * TFTPUtils.h
 *
 *  Created on: 27 de mar. de 2024
 *      Author: ianwillianb
 */

#ifndef TFTPUTILS_H_
#define TFTPUTILS_H_

#include <netinet/in.h>
#include <utility>
#include <string>

namespace TFTP
{
	class TFTPUtils
	{
		public:
			TFTPUtils()=default;

			static std::pair<bool, sockaddr_in> ResolveNetworkIPV4Address(const std::string& address);

			~TFTPUtils()=default;
	};
}

#endif /* TFTPUTILS_H_ */
