/*
 * TFTPClient.h
 *
 *  Created on: 26 de mar. de 2024
 *  Author: ianwillianb
 */

#ifndef TFTPCLIENT_H_
#define TFTPCLIENT_H_

#include <string>
#include <cstdint>
#include <vector>
#include <memory>
#include <netinet/in.h>
#include <arpa/tftp.h>
#include "TFTPDefinitions.h"

namespace TFTP
{
	class TFTPClient
	{
		public:

			TFTPClient(const std::string& server_address, const uint16_t server_port = TFTP_DEFAULT_PORT);

			/* TFTP Get */
			template<typename T>
			std::pair<TFTP::ErrorCode, T> Get(const std::string& remote_path);

			const std::pair<ErrorCode, size_t> Get(const std::string& remote_path, std::shared_ptr<uint8_t> ptr,
					const size_t buffer_size);

			const ErrorCode GetToPath(const std::string& remote_path, const std::string& local_path);

			/* TFTP Put */
			const ErrorCode Put(const std::string& remote_path, const std::string& data);

			const ErrorCode Put(const std::string& remote_path, const std::vector<uint8_t>& data);

			const ErrorCode Put(const std::string& remote_path, std::shared_ptr<uint8_t> data, const size_t data_size);

			/**
			 * Not thread safe, in order to ensure the error message is returned
			 * in buffer container use the following APIs:
			 * Get<std::string>
			 * Get<std::vector>
			 * Get(...,std::shared_ptr<uint8_t> ptr, const size_t buffer_size),
			 * make sure buffer_size is at least SEGSIZE/512 bytes.
			 * This method is required to obtain error messages issues by the server
			 * on GetToPath.
			 * */
			const std::string GetLastErrorMessage() const;

			/**
			 * Transfer a file from local to remote
			 * */
			const ErrorCode PutToPath(const std::string& remote_path, const std::string& local_path);

			~TFTPClient()=default;

		private:

			struct BufferPtrWrapper
			{
				uint8_t* ptr_head{nullptr};
				uint8_t* ptr_pos{nullptr};
			};

			static constexpr time_t DEFAULT_RECV_TIMEOUT{5};
			static constexpr time_t DEFAULT_SEND_TIMEOUT{1};

			std::string m_server_address{};
			uint16_t m_server_port{};
			bool m_init_status{};
			timeval m_recv_timeout_secs{DEFAULT_RECV_TIMEOUT,0};
			timeval m_send_timeout_secs{DEFAULT_SEND_TIMEOUT,0};
			std::string m_last_reported_error_msg{};

			//UDP socket FD local
			int m_sock_fd{-1};
			//Server socket input address
		    sockaddr_in serv_addr{};

		    ErrorCode AssertSocket();
		    ErrorCode AssertRemoteAddress();
		    ErrorCode AssertState();
		    ErrorCode AssertRemotePath(const std::string& remote_path);
		    TFTP::TFPT_PKT_RESULT AssertPacket(const tftphdr& pkt, const ssize_t recv_seg_size);

		    ErrorCode ReadWriteRequest(const std::string& remote_path, const uint8_t op_code);
		    ErrorCode Ack(const uint16_t block_num);
		    ErrorCode SigError(const uint16_t err_code);
		    template<typename T>
		    ErrorCode GetRequest(const std::string& file_path, T& file, const size_t buffer_size = 0);
		    template<typename T>
			ErrorCode PutRequest(const std::string& file_path, T& file, const size_t buffer_size);
		    template<typename T>
		    TFTP::ErrorCode Assign(T& obj, uint8_t* input_ptr_begin, const size_t payload_size, const size_t buffer_size = 0);
		    template<typename T>
		    TFTP::ErrorCode Append(T& obj, uint8_t* input_ptr_begin, const size_t payload_size, const size_t buffer_size = 0);
		    template<typename T>
		    void Clear(T& obj, const size_t buffer_size = 0);
		    template<typename T>
		    std::pair<uint8_t*, size_t> ReadBlock(const T& file, const size_t block_num, const size_t file_size);
	};
}

#endif /* TFTPCLIENT_H_ */
