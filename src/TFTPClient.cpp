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

#define SOCKET_NOT_ASSERTED (m_sock_fd < 0)
#define SOCKET_ASSERTED (m_sock_fd >= 0)

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
std::pair<uint8_t*, size_t> TFTPClient::ReadBlock(const T& file, const size_t block_num, const size_t file_size)
{
	return ReadBlock(file.data(), block_num, file_size);
}
template<>
std::pair<uint8_t*, size_t> TFTPClient::ReadBlock(const BufferPtrWrapper& obj, const size_t block_num, const size_t file_size)
{
	const size_t block_start_index{block_num * TFTP::TFTP_MAX_WR_PAYLOAD_SIZE};
	uint8_t* head_ptr{nullptr};
	size_t read_size{0};

	if(file_size > block_start_index)
	{
		head_ptr = obj.ptr_head + block_start_index;
		// A whole block can be read from file
		if((block_start_index + TFTP::TFTP_MAX_WR_PAYLOAD_SIZE) <= file_size)
		{
			read_size = TFTP::TFTP_MAX_WR_PAYLOAD_SIZE;
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

/* TFTP Methods */
TFTPClient::TFTPClient(const std::string& server_address, const uint16_t server_port) : m_server_address{server_address}, m_server_port(server_port)
{
	std::shared_ptr<uint8_t> abc{};
	abc.reset(new uint8_t[32]);
	std::string str{};
	std::vector<uint8_t> vec{};

	AssertState();
}

TFTP::ErrorCode TFTPClient::AssertSocket()
{
	if(SOCKET_NOT_ASSERTED)
	{
		m_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

		if(SOCKET_NOT_ASSERTED)
		{
			perror(__func__);
		}
		else
		{
			// Do nothing
		}
	}

	return SOCKET_ASSERTED ? ErrorCode::NO_ERROR : ErrorCode::SOCKET_OPEN_FAILED;
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

TFTP::ErrorCode TFTPClient::AssertState()
{
	ErrorCode err_code = AssertSocket();

	if(err_code == ErrorCode::NO_ERROR)
	{
		err_code = m_init_status ? ErrorCode::NO_ERROR : AssertRemoteAddress();
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

TFTP::ErrorCode TFTPClient::ReadWriteRequest(const std::string& remote_path, const uint8_t op_code)
{

	ErrorCode err_code{AssertState()};

	if(err_code != ErrorCode::NO_ERROR)
	{
		return err_code;
	}

	uint8_t snd_pkt[SEGSIZE]{0};
	tftphdr* snd_pkt_hdr = reinterpret_cast<tftphdr*>(snd_pkt);

	ssize_t packet_len = sizeof(tftphdr) - sizeof(tftphdr::th_u1);

	err_code = AssertRemotePath(remote_path);
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
		printf("[%s] Error: Remote path %s too long: %ld, max allowed: %ld",
				__func__, remote_path.c_str(), remote_path.size(),
				TFTP::TFTP_MAX_ALLOWED_RQ_WQ_PATH_SIZE);
		return err_code;
	}

	const ssize_t sent_bytes = sendto(m_sock_fd, snd_pkt, packet_len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	printf("[%s] Wrote %ld bytes from %ld packet bytes for RW/RQ\n", __func__, sent_bytes, packet_len);

	return (sent_bytes == packet_len) ? ErrorCode::NO_ERROR : ErrorCode::SEND_REQ_ERROR;
}

TFTP::ErrorCode TFTPClient::Ack(const uint16_t block_num)
{
	tftphdr ack_header{};
	ack_header.th_opcode = htons(ACK);
	ack_header.th_block = htons(block_num);
    ssize_t bytes_sent = sendto(m_sock_fd, &ack_header, TFTP::TFTP_RWA_HEADER_SIZE, 0,
                                (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if(bytes_sent != TFTP::TFTP_RWA_HEADER_SIZE)
    {
    	perror("Failed to send ACK packet");
    	return ErrorCode::SEND_ACK_ERROR;
    }

    return ErrorCode::NO_ERROR;
}

TFTP::ErrorCode TFTPClient::SigError(const uint16_t err_code)
{
	uint8_t buffer[SEGSIZE]{0};
	tftphdr* ack_header{reinterpret_cast<tftphdr*>(buffer)};
	ack_header->th_opcode = htons(ERROR);
	ack_header->th_code = htons(err_code);
	const std::string err_msg{TFTP::TFTPErrorCodeToString(err_code)};
	strncpy(static_cast<char *>(ack_header->th_msg), err_msg.c_str(), TFTP::TFTP_MAX_WR_PAYLOAD_SIZE);
    ssize_t bytes_sent = sendto(m_sock_fd, &ack_header, TFTP::TFTP_RWA_HEADER_SIZE + err_msg.length() + 1, 0,
                                (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if(bytes_sent != TFTP::TFTP_RWA_HEADER_SIZE)
    {
    	perror("Failed to send ACK packet");
    	return ErrorCode::SEND_ACK_ERROR;
    }

    return ErrorCode::NO_ERROR;
}

template<typename T>
TFTP::ErrorCode TFTPClient::GetRequest(const std::string& file_path, T& file, const size_t buffer_size)
{
	ErrorCode err_code = ReadWriteRequest(file_path, RRQ);
	if(err_code != ErrorCode::NO_ERROR)
	{
		return err_code;
	}

	//Set a receive timeout according to configured send timeout window
	if(setsockopt(m_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &m_recv_timeout_secs, sizeof(m_recv_timeout_secs)) != 0)
	{
		perror("Failed to set receive timeout window");
		return ErrorCode::SET_SOCK_OPT_ERROR;
	}

	time_t last_valid_op_step = time(NULL);
	socklen_t serv_addr_size = sizeof(serv_addr);
	uint16_t expected_block_num{1};
	bool ongoing_transfer{true};

	//Receive file or issue error
	while(ongoing_transfer)
	{
		uint8_t buffer[SEGSIZE]{0};
		tftphdr* rcv_pkt{reinterpret_cast<tftphdr*>(buffer)};
		ssize_t read_size = recvfrom(m_sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, &serv_addr_size);
		if(read_size != -1)
		{
			printf("[%s] Got %ld bytes from TFTP server\n", __func__, read_size);
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
				Ack(expected_block_num);
				expected_block_num++;
				last_valid_op_step = time(NULL);
			}
			else if(difftime(time(NULL), last_valid_op_step) > m_recv_timeout_secs.tv_sec)
			{
				printf("[%s] Receive operation has timeout after %ld seconds, aborting...\n",
						__func__, m_recv_timeout_secs.tv_sec);
				//Too many invalid packets, signal error and give up
				SigError((result == TFTP::TFPT_PKT_RESULT::PKT_UNEXPECTED_OPCODE) ? EBADOP : EBADID);
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
			SigError(EUNDEF);
			const int sys_errno = errno;
			perror("Failed to receive packet");
			err_code = (sys_errno == EAGAIN) ? TFTP::ErrorCode::OPERATION_TIMEOUT : TFTP::ErrorCode::RECV_ERROR;
			return err_code;
		}
	}

	return TFTP::ErrorCode::NO_ERROR;
}

template<typename T>
TFTP::ErrorCode TFTPClient::PutRequest(const std::string& file_path, T& file, const size_t buffer_size)
{
	ErrorCode err_code = ReadWriteRequest(file_path, WRQ);
	if(err_code != ErrorCode::NO_ERROR)
	{
		return err_code;
	}

	//Set a receive timeout according to configured send timeout window
	if(setsockopt(m_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &m_recv_timeout_secs, sizeof(m_recv_timeout_secs)) != 0)
	{
		perror("Failed to set receive timeout window");
		return ErrorCode::SET_SOCK_OPT_ERROR;
	}

	time_t last_valid_op_step = time(NULL);
	socklen_t serv_addr_size = sizeof(serv_addr);
	uint16_t expected_block_num{1};
	bool ongoing_transfer{true};

	//Receive file or issue error
	while(ongoing_transfer)
	{
		/* Transmit or retransmit block */
		//ssize_t send_size = sendto(m_sock_fd, )

		uint8_t buffer[SEGSIZE]{0};
		tftphdr* rcv_pkt{reinterpret_cast<tftphdr*>(buffer)};
		ssize_t read_size = recvfrom(m_sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, &serv_addr_size);
		if(read_size != -1)
		{
			printf("[%s] Got %ld bytes from TFTP server\n", __func__, read_size);
			const TFTP::TFPT_PKT_RESULT result = AssertPacket(*rcv_pkt, read_size);
			bool valid_packet{false};

			switch(result)
			{
				case TFTP::TFPT_PKT_RESULT::PKT_SIG_ERROR:
				{
					printf("[%s] Packet error signaled by server, error code: %d\n",__func__, ntohs(rcv_pkt->th_code));
					//Invalidate any received data
					//Clear(file, buffer_size);
					// An error message may be included to provide additional details about the error code
					if(rcv_pkt->th_msg)
					{
						printf("[%s] TFTP server reported error message: %s\n", __func__, rcv_pkt->th_msg);
						// Won't treat return code for errors in order to not overwrite first issued error
						//Assign(file, &buffer[TFTP::TFTP_RWA_HEADER_SIZE], read_size - TFTP::TFTP_RWA_HEADER_SIZE, buffer_size);
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
//				const TFTP::ErrorCode append_err = Append(file, &buffer[TFTP::TFTP_RWA_HEADER_SIZE],
//								read_size - TFTP::TFTP_RWA_HEADER_SIZE, buffer_size);
//				if(append_err != TFTP::ErrorCode::NO_ERROR)
//				{
//					return append_err;
//				}

				printf("Sending ACK for block number %d\n", expected_block_num);
				Ack(expected_block_num);
				expected_block_num++;
				last_valid_op_step = time(NULL);
			}
			else if(difftime(time(NULL), last_valid_op_step) > m_recv_timeout_secs.tv_sec)
			{
				printf("[%s] Receive operation has timeout after %ld seconds, aborting...\n",
						__func__, m_recv_timeout_secs.tv_sec);
				//Too many invalid packets, signal error and give up
				SigError((result == TFTP::TFPT_PKT_RESULT::PKT_UNEXPECTED_OPCODE) ? EBADOP : EBADID);
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
			SigError(EUNDEF);
			const int sys_errno = errno;
			perror("Failed to receive packet");
			err_code = (sys_errno == EAGAIN) ? TFTP::ErrorCode::OPERATION_TIMEOUT : TFTP::ErrorCode::RECV_ERROR;
			return err_code;
		}
	}

	return TFTP::ErrorCode::NO_ERROR;
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

const TFTP::ErrorCode TFTPClient::GetToPath(const std::string& remote_path, const std::string& local_path)
{
	std::ofstream outfile(local_path, std::ios::binary | std::ios::out | std::ios::trunc);
	if(!outfile)
	{
		printf("[%s] Failed to open/create file in local machine", __func__);
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

const TFTP::ErrorCode TFTPClient::Put(const std::string& remote_path, const std::string& data)
{
	return PutRequest(remote_path, data, data.size() + 1);
}

const TFTP::ErrorCode TFTPClient::Put(const std::string& remote_path, const std::vector<uint8_t>& data)
{
	return PutRequest(remote_path, data, data.size() + 1);
}

const TFTP::ErrorCode TFTPClient::Put(const std::string& remote_path, std::shared_ptr<uint8_t> data, const size_t data_size)
{
	BufferPtrWrapper buffer_ptr{data.get(), data.get()};
	return PutRequest(remote_path, buffer_ptr, data_size);
}

const TFTP::ErrorCode TFTPClient::PutToPath(const std::string& remote_path, const std::string& local_path)
{
	//Use POSIX functions since the map is going to be mapped in memory
    const int fd = open(local_path.c_str(), O_RDONLY);
    if(fd == -1)
    {
    	perror("Failed to open file for transmission");
    	return TFTP::ErrorCode::FILE_OPEN_ERROR;
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
        return TFTP::ErrorCode::FILE_MMAP_ERROR;
    }

    BufferPtrWrapper file_ptr{static_cast<uint8_t*>(file_memmap_ptr), static_cast<uint8_t*>(file_memmap_ptr)};
    const TFTP::ErrorCode err_code = PutRequest(remote_path, file_ptr, file_size);

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
