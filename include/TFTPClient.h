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
#include "SocketWrapper.h"

namespace TFTP
{
    class TFTPClient
    {
        public:

            /**
             * @brief TFTPClient constructor
             * @param server_address Server IP(V4) or hostname
             * @param server_port Server port, defaults to TFTP_DEFAULT_PORT
             */
            TFTPClient(const std::string& server_address, const uint16_t server_port = TFTP_DEFAULT_PORT);

            /* TFTP Get */
            /**
             * @name Get<std::string>, Get<std::vector>
             * @brief Get file from TFTP server
             * @tparam std::string, std::vector
             * @param remote_path Path of file to be transfered from TFTP server
             * @return A pair which contains:
             * Operation result: NO_ERROR if success, otherwise error code
             * File: If result code NO_ERROR the file data contained in typename (std::string, std::vector),
             * otherwise an the container may contain the error message informed by the TFTP server.
             */
            template<typename T>
            std::pair<TFTP::ErrorCode, T> Get(const std::string& remote_path);

            /**
             * @name Get
             * @brief Get file from TFTP server
             * @param remote_path Path of file to be transfered from TFTP server
             * @param ptr Shared pointer to provided buffer
             * @param buffer_size Buffer size in bytes
             * @return A pair which contains:
             * Operation result: NO_ERROR if success, otherwise error code
             * Number of bytes written into the provided buffer.
             * @note If an error is reported by the TFTP server including an error
             * message, the message will be written into the provided buffer.
             */
            const std::pair<ErrorCode, size_t> Get(const std::string& remote_path, std::shared_ptr<uint8_t> ptr,
                    const size_t buffer_size);

            /**
             * @name Get
             * @brief Get file from TFTP server
             * @param remote_path Path of file to be transfered from TFTP server
             * @param ptr Raw pointer to provided buffer
             * @param buffer_size Buffer size in bytes
             * @return A pair which contains:
             * Operation result: NO_ERROR if success, otherwise error code
             * Number of bytes written into the provided buffer.
             * @note If an error is reported by the TFTP server including an error
             * message, the message will be written into the provided buffer.
             */
            const std::pair<ErrorCode, size_t> Get(const std::string& remote_path, uint8_t* ptr, const size_t buffer_size);

            /**
             * @name GetGetToPath
             * @brief Get file from TFTP server and save it to local file system
             * @param remote_path Path of file to be transfered from TFTP server
             * @param local_path Local path where file will be created
             * @return Operation result: NO_ERROR if success, otherwise error code
             * @note If an error is reported by the TFTP server including an error
             * message, the message can be retrieved via GetLastErrorMessage method.
             */
            const ErrorCode GetToPath(const std::string& remote_path, const std::string& local_path);

            /* TFTP Put */
            /**
             * @name Put
             * @brief Transfer data to TFTP server
             * @tparam T std::string, std::vector
             * @param remote_path Absolute path of file which will be transfered to TFTP server
             * @param data Data container: std::string, std::vector
             * @return A pair which contains:
             * Operation result: NO_ERROR if success, otherwise error code
             * Error message: error message reported by TFTP server if error, otherwise empty string
             */
            template<typename T>
            const std::pair<ErrorCode, std::string> Put(const std::string& remote_path, const T& data);

            /**
             * @name Put
             * @brief Transfer data to TFTP server
             * @param remote_path Absolute path of file which will be transfered to TFTP server
             * @param data Shared pointer to data buffer
             * @param data_size Number of bytes in buffer
             * @return A pair which contains:
             * Operation result: NO_ERROR if success, otherwise error code
             * Error message: error message reported by TFTP server if error, otherwise empty string
             */
            const std::pair<ErrorCode, std::string> Put(const std::string& remote_path, const std::shared_ptr<uint8_t> data, const size_t data_size);

            /**
             * @name Put
             * @brief Transfer data to TFTP server
             * @param remote_path Absolute path of file which will be transfered to TFTP server
             * @param data Raw pointer to data buffer
             * @param data_size Number of bytes in buffer
             * @return A pair which contains:
             * Operation result: NO_ERROR if success, otherwise error code
             * Error message: error message reported by TFTP server if error, otherwise empty string
             */
            const std::pair<ErrorCode, std::string> Put(const std::string& remote_path, const uint8_t* data, const size_t data_size);

            /**
             * @name PutFromLocalPath
             * @brief Transfer a local file to TFTP server
             * @param remote_path Absolute path of file which will be transfered to TFTP server
             * @param local_path Path of file which will be transfer to TFTP server
             * @return A pair which contains:
             * Operation result: NO_ERROR if success, otherwise error code
             * Error message: error message reported by TFTP server if error, otherwise empty string
             */
            const std::pair<ErrorCode, std::string> PutFromLocalPath(const std::string& remote_path, const std::string& local_path);

            /* Getters and Setters */
            /**
             * @name GetLastErrorMessage
             * @brief Get last error message reported by TFTP server
             * @return Error message, of an empty string if no error message has
             * been reported.
             * @note Not thread safe, in order to ensure the error message is returned
             * in buffer container use the following APIs:
             * Get<std::string>
             * Get<std::vector>
             * In regards to Get(...,std::shared_ptr<uint8_t> ptr, const size_t buffer_size),
             * make sure buffer_size is at least SEGSIZE/512 bytes.
             * This method is required to obtain error messages issues by the server
             * on GetToPath.
             * */
            const std::string GetLastErrorMessage() const;

            /**
             * @name GetMaxRetransmissions
             * @brief Get max number of retransmission of segments for Put requests
             * @return Max number of retransmissions
             */
            const uint32_t GetMaxRetransmissions() const;

            /**
             * @name SetMaxRetransmissions
             * @brief  Set max number of retransmission of segments for Put requests
             * @param max_retransmissions Max number of retransmissions, zero if unlimited
             */
            void SetMaxRetransmissions(const uint32_t max_retransmissions);

            /**
             * @name GetReceiveTimeout
             * @brief Get the timeout value in seconds for Get transfers
             * @return Timeout in seconds
             */
            const time_t GetReceiveTimeout() const;

            /**
             * @name SetReceiveTimeout
             * @brief Set the timeout value in seconds for Get transfers
             * @param receive_timeout_seconds Timeout in seconds
             */
            void SetReceiveTimeout(const time_t receive_timeout_seconds);

            /**
             * @name GetSendTimeout
             * @brief Get the timeout value in seconds for Put transfers
             * @return Timeout in seconds
             */
            const time_t GetSendTimeout() const;

            /**
             * @name SetSendTimeout
             * @brief Set the timeout value in seconds for Put transfers
             * @param receive_timeout_seconds Timeout in seconds
             */
            void SetSendTimeout(const time_t receive_timeout_seconds);

            /**
             * @name GetServerAddress
             * @brief Get the TFTP server address
             * @return The TFTP server address
             */
            const std::string& GetServerAddress() const;

            /**
             * @name GetServerPort
             * @brief Get the TFTP server port
             * @return The TFTP server port
             */
            const uint16_t GetServerPort() const;

            /**
             * @name ~TFTPClient
             * @brief TFTPClient default destructor
             */
            ~TFTPClient()=default;

        private:

            /**
             * @name BufferPtrWrapper
             * @brief Wrapper object for pointer head and current posistion.
             * */
            struct BufferPtrWrapper
            {
                uint8_t* ptr_head{nullptr};
                uint8_t* ptr_pos{nullptr};
            };

            /* Default values */
            static constexpr time_t DEFAULT_RECV_TIMEOUT{5};
            static constexpr time_t DEFAULT_SEND_TIMEOUT{5};
            static constexpr uint32_t DEFAULT_PUT_MAX_RETRANSMISSIONS{1024};

            /* TFTP Server Parameters */
            std::string m_server_address{};
            uint16_t m_server_port{};
            sockaddr_in serv_addr{};

            /* Put/Get configurations */
            timeval m_recv_timeout_secs{DEFAULT_RECV_TIMEOUT,0};
            timeval m_send_timeout_secs{DEFAULT_SEND_TIMEOUT,0};
            uint32_t m_max_retransmissions{DEFAULT_PUT_MAX_RETRANSMISSIONS};

            /* Internal states */
            bool m_init_status{};
            std::string m_last_reported_error_msg{};

            /* Soft Aserts */
            std::pair<ErrorCode, SocketWrapper> AssertSocket();
            ErrorCode AssertRemoteAddress();
            std::pair<ErrorCode, SocketWrapper> AssertState();
            ErrorCode AssertRemotePath(const std::string& remote_path);
            TFTP::TFPT_PKT_RESULT AssertPacket(const tftphdr& pkt, const ssize_t recv_seg_size);

            /* TFTP Protocol Handling */
            /**
             * @name ReadWriteRequest
             * @brief Transmit a Get/Put request segment
             * @param remote_path Remote file path for Get/Put
             * @param op_code Opcode signaling Get/Put request
             * @param sock_fd Socket file descriptor
             * @return Operation result or error code
             */
            ErrorCode ReadWriteRequest(const std::string& remote_path, const uint8_t op_code, const int sock_fd);

            /**
             * @name Ack
             * @brief Sends an acknowledgment packet
             * @param block_num Block number being acknowledged
             * @param sock_fd Socket file descriptor
             * @param server_sockaddr Server allocated socket address
             * @return Operation result or error code
             */
            ErrorCode Ack(const uint16_t block_num, const int sock_fd, const sockaddr_in& server_sockaddr);

            /**
             * @name SigError
             * @brief Signals an error to TFTP server
             * @param err_code Error type
             * @param sock_fd Socket file descriptor
             * @param server_sockaddr Server allocated socket address
             * @return Operation result or error code
             */
            ErrorCode SigError(const uint16_t err_code, const int sock_fd, const sockaddr_in& server_sockaddr);

            /**
             * @name GetRequest
             * @brief Performs a Get operation
             * @tparam T std::string, std::vector, std::ofstream
             * @param file_path Remote file path
             * @param file Reference to container where received data will be stored
             * @param buffer_size Buffer size if the container is a pre-allocated buffer
             * @return Operation result or error code
             */
            template<typename T>
            ErrorCode GetRequest(const std::string& file_path, T& file, const size_t buffer_size = 0);

            /**
             * @name PutRequest
             * @brief Performs a Put operation
             * @tparam T std::string, std::vector
             * @param file_path Remote file path which will be created on TFTP server
             * @param file Container which stores the data that will be transmitted
             * @param buffer_size Number of bytes in container
             * @return A pair of: Operation result and server reported error message, if any.
             */
            template<typename T>
            std::pair<ErrorCode, std::string> PutRequest(const std::string& file_path, T& file, const size_t buffer_size);

            /**
             * @name Assign
             * @brief Assign data into container
             * @tparam T std::string, std::vector, BufferPtrWrapper, std::ofstream
             * @param obj Container
             * @param input_ptr_begin Pointer head
             * @param payload_size Number of bytes which will be assigned to the container
             * @param buffer_size Container size, if pre-allocated
             * @return Operation result or error code
             */
            template<typename T>
            TFTP::ErrorCode Assign(T& obj, uint8_t* input_ptr_begin, const size_t payload_size, const size_t buffer_size = 0);

            /**
             * @name Append
             * @brief Append data into container
             * @tparam T std::string, std::vector, BufferPtrWrapper, std::ofstream
             * @param obj Container
             * @param input_ptr_begin Pointer head
             * @param payload_size Number of bytes which will be appended to the container
             * @param buffer_size Container size, if pre-allocated
             * @return Operation result or error code
             */
            template<typename T>
            TFTP::ErrorCode Append(T& obj, uint8_t* input_ptr_begin, const size_t payload_size, const size_t buffer_size = 0);

            /**
             * @name Clear
             * @brief Clear container data
             * @tparam T std::string, std::vector, BufferPtrWrapper, std::ofstream
             * @param obj Container
             * @param buffer_size Container size, if pre-allocated
             */
            template<typename T>
            void Clear(T& obj, const size_t buffer_size = 0);

            /**
             * @name ReadBlock
             * @brief Read a transmission block from a file
             * @tparam T std::string, std::vector, BufferPtrWrapper
             * @param file File or container from where the block will be read
             * @param block_num The block number
             * @param file_size Number of bytes of file, or container
             * @return
             */
            template<typename T>
            std::pair<uint8_t*, uint16_t> ReadBlock(const T& file, const size_t block_num, const size_t file_size);
    };
}

#endif /* TFTPCLIENT_H_ */
