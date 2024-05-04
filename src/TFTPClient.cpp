/*
 * TFTPClient.cpp
 *
 *  Created on: 26 de mar. de 2024
 *  Author: ianwillianb
 */

#include "TFTPClient.h"
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "TFTPUtils.h"

using TFTP::TFTPClient;

/* Definition of the template specializations */
template<>
std::pair<TFTP::ErrorCode, std::vector<uint8_t>> TFTPClient::Get(const std::string& remote_path)
{
	std::vector<uint8_t> container{};
	return {GetRequest<std::vector<uint8_t>>(remote_path, container), container};
}

template<>
std::pair<TFTP::ErrorCode, std::string> TFTPClient::Get(const std::string& remote_path)
{
	std::string container{};
	return {GetRequest<std::string>(remote_path, container), container};
}

template<>
const std::pair<TFTP::ErrorCode, std::string> TFTPClient::Put(const std::string& remote_path, const std::string& data)
{
	if(data.size() == 0)
	{
		return {TFTP::ErrorCode::INVALID_LOCAL_FILE, {}};
	}

	return PutRequest(remote_path, data, data.size() + 1);
}

template<>
const std::pair<TFTP::ErrorCode, std::string> TFTPClient::Put(const std::string& remote_path, const std::vector<uint8_t>& data)
{
	if(data.size() == 0)
	{
		return {TFTP::ErrorCode::INVALID_LOCAL_FILE, {}};
	}

	return PutRequest(remote_path, data, data.size());
}

template<typename T>
TFTP::ErrorCode TFTPClient::Assign(T& obj, uint8_t* input_ptr_begin, const size_t payload_size, const size_t buffer_size)
{
	obj.assign(input_ptr_begin, input_ptr_begin + payload_size);
	return TFTP::ErrorCode::NO_ERROR;
}
template<>
TFTP::ErrorCode TFTPClient::Assign(BufferPtrWrapper& obj, uint8_t* input_ptr_begin,
		const size_t payload_size, const size_t buffer_size)
{
	//Assert if provided buffer has enough memory to contain packet
	if(buffer_size < payload_size)
	{
		printf("[%s] Error: provided buffer cannot fit file\n", __func__);
		return TFTP::ErrorCode::INVALID_BUFFER_SIZE;
	}
	memcpy(obj.ptr_pos, input_ptr_begin, payload_size);
	return TFTP::ErrorCode::NO_ERROR;
}
template<>
TFTP::ErrorCode TFTPClient::Assign(std::ofstream& obj, uint8_t* input_ptr_begin,
		const size_t payload_size, const size_t buffer_size)
{
	return TFTP::ErrorCode::NO_ERROR;
}


template<typename T>
TFTP::ErrorCode TFTPClient::Append(T& obj, uint8_t* input_ptr_begin, const size_t payload_size,
		const size_t buffer_size)
{
	obj.insert(obj.end(), input_ptr_begin, input_ptr_begin + payload_size);
	return TFTP::ErrorCode::NO_ERROR;
}
template<>
TFTP::ErrorCode TFTPClient::Append(BufferPtrWrapper& obj, uint8_t* input_ptr_begin,
		const size_t payload_size, const size_t buffer_size)
{
	const TFTP::ErrorCode result = Assign(obj, input_ptr_begin, payload_size, buffer_size);
	if(result == TFTP::ErrorCode::NO_ERROR)
	{
		obj.ptr_pos += payload_size;
	}
	return result;
}
template<>
TFTP::ErrorCode TFTPClient::Append(std::ofstream& obj, uint8_t* input_ptr_begin,
		const size_t payload_size, const size_t buffer_size)
{
	obj.clear();
	obj.write(reinterpret_cast<const char *>(input_ptr_begin), payload_size);
	return (obj.fail() || obj.bad()) ? TFTP::ErrorCode::FILE_WRITE_ERROR :
			TFTP::ErrorCode::NO_ERROR;
}

template<typename T>
void TFTPClient::Clear(T& obj, const size_t buffer_size)
{
	obj.clear();
}
template<>
void TFTPClient::Clear(BufferPtrWrapper& obj, const size_t buffer_size)
{
	bzero(obj.ptr_head, buffer_size);
}
template<>
void TFTPClient::Clear(std::ofstream& obj, const size_t buffer_size)
{
	(void) obj;
	(void) buffer_size;
}

template<typename T>
std::pair<uint8_t*, uint16_t> TFTPClient::ReadBlock(const T& file, const size_t block_num, const size_t file_size)
{
	uint8_t * head_ptr = (uint8_t *)(file.data());
	return ReadBlock(BufferPtrWrapper{head_ptr, head_ptr}, block_num, file_size);
}
template<>
std::pair<uint8_t*, uint16_t> TFTPClient::ReadBlock(const BufferPtrWrapper& obj, const size_t block_num, const size_t file_size)
{
	const size_t block_start_index{block_num * SEGSIZE};
	uint8_t* head_ptr{nullptr};
	size_t read_size{0};

	if(file_size > block_start_index)
	{
		head_ptr = obj.ptr_head + block_start_index;
		// A whole block can be read from file
		if((block_start_index + SEGSIZE) <= file_size)
		{
			read_size = SEGSIZE;
		}
		//Not a whole block can be read, but there is data to be read
		else
		{
			read_size = file_size - block_start_index;
		}
	}
	else
	{
		//Do nothing, block section is not within file memory
	}

	return {head_ptr, read_size};
}

template<>
std::pair<uint8_t*, uint16_t> TFTPClient::ReadBlock(const std::string& file, const size_t block_num, const size_t file_size)
{
	uint8_t * head_ptr = (uint8_t *)(file.c_str());
	return ReadBlock(BufferPtrWrapper{head_ptr, head_ptr}, block_num, file_size);
}
/* TFTP Methods */
TFTPClient::TFTPClient(const std::string& server_address, const uint16_t server_port) : m_server_address{server_address}, m_server_port(server_port)
{
    AssertRemoteAddress();
}

std::pair<TFTP::ErrorCode, SocketWrapper> TFTPClient::AssertSocket()
{
    SocketWrapper sock_fd{AF_INET, SOCK_DGRAM, 0};
	return {sock_fd ? ErrorCode::NO_ERROR : ErrorCode::SOCKET_OPEN_FAILED, std::move(sock_fd)};
}

TFTP::ErrorCode TFTPClient::AssertRemoteAddress()
{
	//Resolve host name or IPV4 into a sockaddr_in
	std::pair<bool, sockaddr_in> resolved_addr =
			TFTP::TFTPUtils::ResolveNetworkIPV4Address(m_server_address);

	if(resolved_addr.first == false)
	{
		m_init_status = false;
		return ErrorCode::INVALID_REMOTE_ADDR;
	}
	else
	{
		// Do nothing
	}

	/* Set TFTP server address */
	//IPV4 socket
	serv_addr.sin_family = AF_INET;
	//Set server port in network byte order
	serv_addr.sin_port = htons(m_server_port);
	// Set resolved address
	serv_addr.sin_addr = resolved_addr.second.sin_addr;

	m_init_status = true;

	return ErrorCode::NO_ERROR;
}

std::pair<TFTP::ErrorCode, SocketWrapper> TFTPClient::AssertState()
{
    std::pair<TFTP::ErrorCode, SocketWrapper> err_code = AssertSocket();

	if(err_code.first == ErrorCode::NO_ERROR)
	{
		err_code.first = m_init_status ? ErrorCode::NO_ERROR : AssertRemoteAddress();
	}
	else
	{
		// Socket not asserted, no need to resolve address
	}

	return err_code;
}

TFTP::ErrorCode TFTPClient::AssertRemotePath(const std::string& remote_path)
{
	return (remote_path.length() <= TFTP::TFTP_MAX_ALLOWED_RQ_WQ_PATH_SIZE) ?
			ErrorCode::NO_ERROR : ErrorCode::INVALID_REMOTE_PATH;
}

TFTP::TFPT_PKT_RESULT TFTPClient::AssertPacket(const tftphdr& pkt, const ssize_t recv_seg_size)
{
	switch(ntohs(pkt.th_opcode))
	{
		case DATA:
		{
			return (recv_seg_size == SEGSIZE) ?
					TFTP::TFPT_PKT_RESULT::PKT_SIG_PENDING_DATA : TFTP::TFPT_PKT_RESULT::PKT_SIG_EOF;
		}
		case ACK:
		{
			return TFTP::TFPT_PKT_RESULT::PKT_SIG_ACK;
		}
		case ERROR:
		{
			return TFTP::TFPT_PKT_RESULT::PKT_SIG_ERROR;
		}
		default:
		{
			return TFTP::TFPT_PKT_RESULT::PKT_UNEXPECTED_OPCODE;
		}
	}
}

TFTP::ErrorCode TFTPClient::ReadWriteRequest(const std::string& remote_path, const uint8_t op_code, const int sock_fd)
{
	uint8_t snd_pkt[SEGSIZE]{0};
	tftphdr* snd_pkt_hdr = reinterpret_cast<tftphdr*>(snd_pkt);

	ssize_t packet_len = sizeof(tftphdr) - sizeof(tftphdr::th_u1);

	ErrorCode err_code = AssertRemotePath(remote_path);
	if(err_code == ErrorCode::NO_ERROR)
	{
		//Read request opcode
		snd_pkt_hdr->th_opcode = htons(op_code);

		//Remote file path being requested
		const size_t remote_path_sec_len = remote_path.length() + 1;
		packet_len += remote_path_sec_len;
		strncpy(snd_pkt_hdr->th_stuff, remote_path.c_str(), remote_path_sec_len);

		//Only supports ASCII mode, mail mode is not advised and has been deprecated
		strncpy(snd_pkt_hdr->th_stuff + remote_path_sec_len, TFTP::TFTP_MODE_NETASCII.c_str(), TFTP::TFTP_MODE_SECTION_SIZE);
		packet_len += TFTP::TFTP_MODE_SECTION_SIZE;
	}
	else
	{
		printf("[%s] Error: Remote path %s too long: %ld, max allowed: %ld\n",
				__func__, remote_path.c_str(), remote_path.size(),
				TFTP::TFTP_MAX_ALLOWED_RQ_WQ_PATH_SIZE);
		return err_code;
	}

	const ssize_t sent_bytes = sendto(sock_fd, snd_pkt, packet_len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	return (sent_bytes == packet_len) ? ErrorCode::NO_ERROR : ErrorCode::SEND_REQ_ERROR;
}

TFTP::ErrorCode TFTPClient::Ack(const uint16_t block_num, const int sock_fd, const sockaddr_in& server_sockaddr)
{
	tftphdr ack_header{};
	ack_header.th_opcode = htons(ACK);
	ack_header.th_block = htons(block_num);
    ssize_t bytes_sent = sendto(sock_fd, &ack_header, TFTP::TFTP_RWA_HEADER_SIZE, 0,
                                (struct sockaddr*)&server_sockaddr, sizeof(server_sockaddr));

    if(bytes_sent != TFTP::TFTP_RWA_HEADER_SIZE)
    {
    	perror("Failed to send ACK packet");
    	return ErrorCode::SEND_ACK_ERROR;
    }

    return ErrorCode::NO_ERROR;
}

TFTP::ErrorCode TFTPClient::SigError(const uint16_t err_code, const int sock_fd, const sockaddr_in& server_sockaddr)
{
	uint8_t buffer[SEGSIZE]{0};
	tftphdr* ack_header{reinterpret_cast<tftphdr*>(buffer)};
	ack_header->th_opcode = htons(ERROR);
	ack_header->th_code = htons(err_code);
	const std::string err_msg{TFTP::TFTPErrorCodeToString(err_code)};
	strncpy(static_cast<char *>(ack_header->th_msg), err_msg.c_str(), TFTP::TFTP_MAX_WR_PAYLOAD_SIZE);
    ssize_t bytes_sent = sendto(sock_fd, &ack_header, TFTP::TFTP_RWA_HEADER_SIZE + err_msg.length() + 1, 0,
                                (struct sockaddr*)&server_sockaddr, sizeof(server_sockaddr));

    if(bytes_sent != TFTP::TFTP_RWA_HEADER_SIZE)
    {
    	perror("Failed to send error packet");
    	return ErrorCode::SEND_ERR_FAILED;
    }

    return ErrorCode::NO_ERROR;
}

template<typename T>
TFTP::ErrorCode TFTPClient::GetRequest(const std::string& file_path, T& file, const size_t buffer_size)
{
    std::pair<TFTP::ErrorCode, SocketWrapper> state = AssertState();
    if(state.first != ErrorCode::NO_ERROR)
    {

        return state.first;
    }

    TFTP::ErrorCode err_code = ReadWriteRequest(file_path, RRQ, state.second);
    if(err_code != ErrorCode::NO_ERROR)
    {
        return err_code;
    }

    /*
     * Copy the server address for main socket.
     * The TFTP server allocates a new socket and this one
     * will be used in subsequent requests.
     * The copy is modified in recv_from, to this point forward
     * all communications outgoing to the server for the specific file
     * is conducted through this server port.
     * */
    socklen_t serv_addr_size = sizeof(serv_addr);
    sockaddr_in server_allocated_sockaddr{serv_addr};

    //Cache receive timeout to ensure it cannot be changed during transfer
    const timeval receive_timeout{m_recv_timeout_secs};

    //Set a receive timeout according to configured send timeout window
    if(setsockopt(state.second, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) != 0)
    {
        perror("Failed to set receive timeout window");
        return ErrorCode::SET_SOCK_OPT_ERROR;
    }

    time_t last_valid_op_step = time(NULL);
    uint16_t expected_block_num{1};
    bool ongoing_transfer{true};

    //Receive file or issue error
    while(ongoing_transfer)
    {
        uint8_t buffer[SEGSIZE]{0};
        tftphdr* rcv_pkt{reinterpret_cast<tftphdr*>(buffer)};
        ssize_t read_size = recvfrom(state.second, buffer, sizeof(buffer), 0,
                (struct sockaddr *)&server_allocated_sockaddr, &serv_addr_size);
        if(read_size != -1)
        {
            const TFTP::TFPT_PKT_RESULT result = AssertPacket(*rcv_pkt, read_size);
            bool valid_packet{false};

            switch(result)
            {
                case TFTP::TFPT_PKT_RESULT::PKT_SIG_ERROR:
                {
                    printf("[%s] Packet error signaled by server, error code: %d\n",__func__, ntohs(rcv_pkt->th_code));
                    //Invalidate any received data
                    Clear(file, buffer_size);
                    // An error message may be included to provide additional details about the error code
                    if(rcv_pkt->th_msg)
                    {
                        printf("[%s] TFTP server reported error message: %s\n", __func__, rcv_pkt->th_msg);
                        // Won't treat return code for errors in order to not overwrite first issued error
                        Assign(file, &buffer[TFTP::TFTP_RWA_HEADER_SIZE], read_size - TFTP::TFTP_RWA_HEADER_SIZE, buffer_size);
                        //Persist the reported error in class
                        m_last_reported_error_msg = std::string(reinterpret_cast<const char *>(&buffer[TFTP::TFTP_RWA_HEADER_SIZE]),
                                read_size - TFTP::TFTP_RWA_HEADER_SIZE);
                    }
                    return TFTP::ErrorCodeFromTFTPError(ntohs(rcv_pkt->th_code));
                }
                case TFTP::TFPT_PKT_RESULT::PKT_SIG_PENDING_DATA:
                {
                    printf("[%s] Pending file data signaled by server, block number %d\n",__func__,
                            ntohs(rcv_pkt->th_block));
                    valid_packet = (ntohs(rcv_pkt->th_block) == expected_block_num);
                    break;
                }
                case TFTP::TFPT_PKT_RESULT::PKT_SIG_EOF:
                {
                    printf("[%s] EOF signaled by server, block number: %d\n",__func__,
                            ntohs(rcv_pkt->th_block));
                    valid_packet = (ntohs(rcv_pkt->th_block) == expected_block_num);
                    break;
                }
                default:
                {
                    printf("[%s] Unexpected assert packet returned: %s\n", __func__,
                            TFTP::TFPT_PKT_RESULT_ToString(result).c_str());
                    break;
                }
            }

            if(valid_packet)
            {
                const TFTP::ErrorCode append_err = Append(file, &buffer[TFTP::TFTP_RWA_HEADER_SIZE],
                                read_size - TFTP::TFTP_RWA_HEADER_SIZE, buffer_size);
                if(append_err != TFTP::ErrorCode::NO_ERROR)
                {
                    return append_err;
                }

                printf("Sending ACK for block number %d\n", expected_block_num);
                Ack(expected_block_num, state.second, server_allocated_sockaddr);
                expected_block_num++;
                last_valid_op_step = time(NULL);
            }
            else if(difftime(time(NULL), last_valid_op_step) > receive_timeout.tv_sec)
            {
                printf("[%s] Receive operation has timeout after %ld seconds, aborting...\n",
                        __func__, receive_timeout.tv_sec);
                //Too many invalid packets, signal error and give up
                SigError((result == TFTP::TFPT_PKT_RESULT::PKT_UNEXPECTED_OPCODE) ? EBADOP : EBADID, state.second, server_allocated_sockaddr);
                return ErrorCode::OPERATION_TIMEOUT;
            }
            else
            {
                //Do nothing, wait for retransmission of a valid packet
            }

            ongoing_transfer = (result == TFTP::TFPT_PKT_RESULT::PKT_SIG_PENDING_DATA);
        }
        else
        {
            //Signal an error to prevent server from keep retransmission
            SigError(EUNDEF, state.second, server_allocated_sockaddr);
            const int sys_errno = errno;
            perror("Failed to receive packet");
            err_code = (sys_errno == EAGAIN) ? TFTP::ErrorCode::OPERATION_TIMEOUT : TFTP::ErrorCode::RECV_ERROR;
            return err_code;
        }
    }

    return TFTP::ErrorCode::NO_ERROR;
}

template<typename T>
std::pair<TFTP::ErrorCode, std::string>TFTPClient::PutRequest(const std::string& file_path, T& file, const size_t buffer_size)
{
    std::pair<TFTP::ErrorCode, SocketWrapper> state = AssertState();
    if(state.first != ErrorCode::NO_ERROR)
    {
        return {state.first, {}};
    }

    ErrorCode err_code = ReadWriteRequest(file_path, WRQ, state.second);
    if(err_code != ErrorCode::NO_ERROR)
    {
        printf("err code: %d\n", (int) err_code);
        return {err_code, {}};
    }

    /*
     * Copy the server address for main socket.
     * The TFTP server allocates a new socket and this one
     * will be used in subsequent requests.
     * The copy is modified in recv_from, to this point forward
     * all communications outgoing to the server for the specific file
     * is conducted through this server port.
     * */
    socklen_t serv_addr_size = sizeof(serv_addr);
    sockaddr_in server_allocated_sockaddr{serv_addr};

    /*
     * Cache send timeout, so its value is kept during this operation
     * event if modified after operation has started
     **/
    const timeval send_timeout{m_send_timeout_secs};

    //Set a receive timeout according to configured receive timeout window
    if(setsockopt(state.second.GetSocketFD(), SOL_SOCKET, SO_RCVTIMEO, &send_timeout, sizeof(send_timeout)) != 0)
    {
        perror("Failed to set receive timeout window");
        return {ErrorCode::SET_SOCK_OPT_ERROR, {}};
    }

    time_t last_valid_op_step = time(NULL);
    uint16_t last_client_acked_block{0};
    size_t file_block_pos{0};
    uint32_t retransmissions_count{0};
    bool put_request_ack_status{false};
    bool reached_eof{false};
    bool ongoing_transfer{true};

    //Receive file or issue error
    while(ongoing_transfer)
    {
        uint8_t buffer[SEGSIZE]{0};
        tftphdr* rcv_pkt{reinterpret_cast<tftphdr*>(buffer)};
        ssize_t read_size = recvfrom(state.second, buffer, sizeof(buffer), 0, (struct sockaddr *)&server_allocated_sockaddr, &serv_addr_size);
        if(read_size != -1)
        {
            const TFTP::TFPT_PKT_RESULT result = AssertPacket(*rcv_pkt, read_size);
            bool valid_packet{false};

            switch(result)
            {
                case TFTP::TFPT_PKT_RESULT::PKT_SIG_ERROR:
                {
                    std::string error_msg{};
                    printf("[%s] Packet error signaled by server, error code: %d\n",__func__, ntohs(rcv_pkt->th_code));
                    // An error message may be included to provide additional details about the error code
                    if(rcv_pkt->th_msg)
                    {
                        printf("[%s] TFTP server reported error message: %s\n", __func__, rcv_pkt->th_msg);
                        //Persist the reported error in class
                        error_msg = std::string(reinterpret_cast<const char *>(&buffer[TFTP::TFTP_RWA_HEADER_SIZE]),
                                read_size - TFTP::TFTP_RWA_HEADER_SIZE);
                        m_last_reported_error_msg = error_msg;
                    }
                    return {TFTP::ErrorCodeFromTFTPError(ntohs(rcv_pkt->th_code)), error_msg};
                }
                case TFTP::TFPT_PKT_RESULT::PKT_SIG_ACK:
                {
                    valid_packet = true;
                    const uint16_t server_acked_block_num = ntohs(rcv_pkt->th_block);

                    printf("[%s] Received ACK %d\n", __func__, server_acked_block_num);

                    //Last block acknowledged is the last one sent
                    if((last_client_acked_block + 1) == server_acked_block_num)
                    {
                        last_client_acked_block = ntohs(rcv_pkt->th_block);
                        retransmissions_count = 0;
                        printf("[%s] Server acknowledged block: %d\n", __func__, last_client_acked_block);

                        //Keep transmitting next blocks
                        if(reached_eof == false)
                        {
                            file_block_pos++;
                        }
                        //EOF reached, finish operation
                        else
                        {
                            Ack(last_client_acked_block, state.second, server_allocated_sockaddr);
                            ongoing_transfer = false;
                            continue;
                        }
                    }
                    //Server is requesting a block retransmission
                    else if(put_request_ack_status)
                    {
                        printf("[%s] Server not acknowledged last sent block, retransmitting...\n", __func__);
                        retransmissions_count++;

                        // Check if max retransmissions attempts has been reached
                        if(m_max_retransmissions && (retransmissions_count > m_max_retransmissions))
                        {
                            printf("[%s] Error reached max number of retransmissions on put request: %u",
                                    __func__, m_max_retransmissions);
                            SigError(EBADOP, state.second, server_allocated_sockaddr);
                            return {TFTP::ErrorCode::MAX_BLOCK_RETRANS, {}};
                        }

                        //Only retransmit if the ACK block number, is the last ACK confirmed
                        if (server_acked_block_num != last_client_acked_block)
                        {
                            continue;
                        }
                    }

                    // A valid acknowledgment has been received
                    put_request_ack_status = true;

                    /* Transmit or retransmit block */
                    const std::pair<uint8_t*, uint16_t> file_block{ReadBlock(file, file_block_pos, buffer_size)};
                    uint8_t transmission_buffer[SEGSIZE]{0};
                    tftphdr* transmission_segment = reinterpret_cast<tftphdr*>(transmission_buffer);
                    transmission_segment->th_opcode = htons(DATA);
                    transmission_segment->th_block = htons(last_client_acked_block + 1);

                    /* Check if trying to read out of file bounds */
                    if(file_block.first != nullptr)
                    {
                        memcpy(transmission_segment->th_data, file_block.first, file_block.second);
                        reached_eof = (file_block.second > 0 && file_block.second < SEGSIZE);
                    }
                    else
                    {
                        /*
                         * The server has not detected the EOF since the last block took the whole segment.
                         * In this particular case send an empty header on next block.
                         * */
                        if((file_block_pos*SEGSIZE) == buffer_size)
                        {
                            reached_eof = true;
                        }
                        else
                        {
                            printf("[%s] Error: trying to read out of bound of provided file, block number %d, buffer_size: %ld\n",
                                    __func__, last_client_acked_block, buffer_size);
                            SigError(EACCESS, state.second, server_allocated_sockaddr);
                            return {TFTP::ErrorCode::INVALID_LOCAL_FILE, {}};
                        }
                    }

                    printf("[%s] Transmitting block number %ld\n", __func__, file_block_pos + 1);
                    const ssize_t segment_size{file_block.second + TFTP::TFTP_RWA_HEADER_SIZE};
                    const ssize_t bytes_sent = sendto(state.second, transmission_buffer, segment_size,
                            0, (struct sockaddr *)&server_allocated_sockaddr, sizeof(server_allocated_sockaddr));

                    if(segment_size != bytes_sent)
                    {
                        if(bytes_sent < 0)
                        {
                            perror("Failed to transmit file block in put request");
                        }
                        SigError(EUNDEF, state.second, server_allocated_sockaddr);
                        return {TFTP::ErrorCode::SEND_ERROR, {}};
                    }

                    break;
                }
                default:
                {
                    printf("[%s] Unexpected assert packet returned: %s\n", __func__,
                            TFTP::TFPT_PKT_RESULT_ToString(result).c_str());
                    break;
                }
            }

            if(valid_packet)
            {
                last_valid_op_step = time(NULL);
            }
            else if(difftime(time(NULL), last_valid_op_step) > send_timeout.tv_sec)
            {
                printf("[%s] Put operation has timeout after %ld seconds, aborting...\n",
                        __func__, send_timeout.tv_sec);
                //Too many invalid packets, signal error and give up
                SigError((result == TFTP::TFPT_PKT_RESULT::PKT_UNEXPECTED_OPCODE) ? EBADOP : EBADID,
                        state.second, server_allocated_sockaddr);
                return {ErrorCode::OPERATION_TIMEOUT, {}};
            }
            else
            {
                //Do nothing, wait for retransmission of a valid packet
            }
        }
        else
        {
            const int sys_errno = errno;
            perror("Failed to receive packet");
            //Signal an error to prevent server from keep retransmission
            SigError(EUNDEF, state.second, server_allocated_sockaddr);
            err_code = (sys_errno == EAGAIN) ? TFTP::ErrorCode::OPERATION_TIMEOUT : TFTP::ErrorCode::SEND_REQ_ERROR;
            return {err_code, {}};
        }
    }

    printf("[%s] Put request to %s finished successfully!\n", __func__, file_path.c_str());

    return {TFTP::ErrorCode::NO_ERROR, {}};
}

const std::pair<TFTP::ErrorCode, size_t> TFTPClient::Get(const std::string& remote_path, std::shared_ptr<uint8_t> ptr, const size_t buffer_size)
{
	if(ptr == nullptr)
	{
		return{TFTP::ErrorCode::INVALID_BUFFER, 0};
	}

	BufferPtrWrapper mutable_ptr{ptr.get(), ptr.get()};
	return {GetRequest(remote_path, mutable_ptr, buffer_size), mutable_ptr.ptr_pos - mutable_ptr.ptr_head};
}

const std::pair<TFTP::ErrorCode, size_t> TFTPClient::Get(const std::string& remote_path, uint8_t* ptr, const size_t buffer_size)
{
	if(ptr == nullptr)
	{
		return{TFTP::ErrorCode::INVALID_BUFFER, 0};
	}

	BufferPtrWrapper mutable_ptr{ptr, ptr};
	return {GetRequest(remote_path, mutable_ptr, buffer_size), mutable_ptr.ptr_pos - mutable_ptr.ptr_head};
}

const TFTP::ErrorCode TFTPClient::GetToPath(const std::string& remote_path, const std::string& local_path)
{
	std::ofstream outfile(local_path, std::ios::binary | std::ios::out | std::ios::trunc);
	if(!outfile)
	{
		printf("[%s] Failed to open/create file in local machine\n", __func__);
		return TFTP::ErrorCode::FILE_OPEN_ERROR;
	}


	const TFTP::ErrorCode err_code = GetRequest(remote_path, outfile);
	//Close the file, so it is flushed to FS
	outfile.close();

	//If errors occurred close the file
	if ((err_code != TFTP::ErrorCode::NO_ERROR) && (std::remove(local_path.c_str()) != 0))
	{
		perror("Error deleting file");
	}

	return err_code;
}

const std::pair<TFTP::ErrorCode, std::string> TFTPClient::Put(const std::string& remote_path, const std::shared_ptr<uint8_t> data, const size_t data_size)
{
	BufferPtrWrapper buffer_ptr{data.get(), data.get()};
	return PutRequest(remote_path, buffer_ptr, data_size);
}

const std::pair<TFTP::ErrorCode, std::string> TFTPClient::Put(const std::string& remote_path, const uint8_t* data, const size_t data_size)
{
	BufferPtrWrapper buffer_ptr{const_cast<uint8_t *>(data), const_cast<uint8_t *>(data)};
	return PutRequest(remote_path, buffer_ptr, data_size);
}

const std::pair<TFTP::ErrorCode, std::string> TFTPClient::PutFromLocalPath(const std::string& remote_path, const std::string& local_path)
{
	//Use POSIX functions since the map is going to be mapped in memory
    const int fd = open(local_path.c_str(), O_RDONLY);
    if(fd == -1)
    {
    	perror("Failed to open file for transmission");
    	return {TFTP::ErrorCode::FILE_OPEN_ERROR, {}};
    }

    // Determine the size of the file
    const off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Map file into memory to avoid copies while reading the blocks,
    // which prevents frequent heap allocation
    void* file_memmap_ptr = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_memmap_ptr == MAP_FAILED)
    {
        perror("Failed to map file to be transmitted in memory");
        close(fd);
        return {TFTP::ErrorCode::FILE_MMAP_ERROR, {}};
    }

    BufferPtrWrapper file_ptr{static_cast<uint8_t*>(file_memmap_ptr), static_cast<uint8_t*>(file_memmap_ptr)};
    const auto err_code = PutRequest(remote_path, file_ptr, file_size);

    // Un-map the memory-mapped file
    munmap(file_memmap_ptr, file_size);

    // Close the file
    close(fd);

    return err_code;
}

const std::string TFTPClient::GetLastErrorMessage() const
{
	return m_last_reported_error_msg;
}

/* Getters and Setters */
const uint32_t TFTPClient::GetMaxRetransmissions() const
{
	return m_max_retransmissions;
}

void TFTPClient::SetMaxRetransmissions(const uint32_t max_retransmissions)
{
	m_max_retransmissions = max_retransmissions;
}

const time_t TFTPClient::GetReceiveTimeout() const
{
	return m_recv_timeout_secs.tv_sec;
}

void TFTPClient::SetReceiveTimeout(const time_t receive_timeout_seconds)
{
	m_recv_timeout_secs.tv_sec = receive_timeout_seconds;
}

const time_t TFTPClient::GetSendTimeout() const
{
	return m_send_timeout_secs.tv_sec;
}

void TFTPClient::SetSendTimeout(const time_t receive_timeout_seconds)
{
	m_send_timeout_secs.tv_sec = receive_timeout_seconds;
}

const std::string& TFTPClient::GetServerAddress() const
{
	return m_server_address;
}

const uint16_t TFTPClient::GetServerPort() const
{
	return m_server_port;
}

