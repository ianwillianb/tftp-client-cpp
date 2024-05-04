#include <cstdint>
#include <string>
#include <arpa/tftp.h>

namespace TFTP
{
	enum class TFPT_PKT_RESULT : uint8_t
	{
		PKT_UNEXPECTED_OPCODE,
		PKT_SIG_ERROR,
		PKT_SIG_ACK,
		PKT_SIG_PENDING_DATA,
		PKT_SIG_EOF
	};

	enum class ErrorCode : uint8_t
	{
		NO_ERROR,			 /* No error */
		SOCKET_OPEN_FAILED,  /* Failed to create UDP socket */
		INVALID_REMOTE_ADDR, /* Invalid remote IPV4 address or hostname */
		INVALID_REMOTE_PATH, /* Remote path is too long */
		INVALID_BUFFER,		 /* Provided buffer is nullptr */
		INVALID_BUFFER_SIZE, /* Provided buffer has not enough length to fit file */
		FILE_OPEN_ERROR, 	 /* Failed to open file in local machine for writing or reading */
		FILE_WRITE_ERROR,    /* Failed to write to local file */
		FILE_MMAP_ERROR, 	 /* Failed to map a local file into memory */
		SEND_REQ_ERROR,		 /* Error on request transmission */
		SEND_ACK_ERROR,		 /* Error on ACK transmission */
		SEND_ERR_FAILED,     /* Failed on ERROR transmission */
		SET_SOCK_OPT_ERROR,  /* Error on setsockopt */
		RECV_ERROR,   		 /* Failed to receive packets from server */
		SEND_ERROR,   		 /* Failed to send file blocks to server */
		OPERATION_TIMEOUT,   /* Read timeout */
		MAX_BLOCK_RETRANS,   /* Max number of retransmissions has been reached during put operation */
		INVALID_LOCAL_FILE,  /* Local file is invalid, null, or provided file size is invalid */
		UNDEF_ERROR,		 /* Generic error code, error cause might be set in message attribute */
		NOTFOUND_ERROR,	     /* File not found */
		ACCESS_ERROR,   	 /* Access violation */
		NOSPACE_ERROR,		 /* Disk full or allocation exceeded */
		BADOP_ERROR, 		 /* Illegal TFTP operation */
		BADID_ERROR, 		 /* Unknown transfer ID */
		EXISTS_ERROR,		 /* File already exists */
		NOUSER_ERROR,		 /* No such user */
	};


	static inline const std::string TFPT_PKT_RESULT_ToString(const TFPT_PKT_RESULT result)
	{
		switch(result)
		{
			case TFPT_PKT_RESULT::PKT_UNEXPECTED_OPCODE:
			{
				return {"PKT_UNEXPECTED_OPCODE"};
			}
			case TFPT_PKT_RESULT::PKT_SIG_ERROR:
			{
				return {"PKT_SIG_ERROR"};
			}
			case TFPT_PKT_RESULT::PKT_SIG_ACK:
			{
				return {"PKT_SIG_ACK"};
			}
			case TFPT_PKT_RESULT::PKT_SIG_PENDING_DATA:
			{
				return {"PKT_SIG_PENDING_DATA"};
			}
			case TFPT_PKT_RESULT::PKT_SIG_EOF:
			{
				return {"PKT_SIG_EOF"};
			}
			default:
			{
				return {"UNKNOWN"};
			}
		}
	}

	static inline ErrorCode ErrorCodeFromTFTPError(const uint16_t err_code)
	{
		switch(err_code)
		{
			case EUNDEF:
			{
				return ErrorCode::UNDEF_ERROR;
			}
			case ENOTFOUND:
			{
				return ErrorCode::NOTFOUND_ERROR;
			}
			case EACCESS:
			{
				return ErrorCode::ACCESS_ERROR;
			}
			case ENOSPACE:
			{
				return ErrorCode::NOSPACE_ERROR;
			}
			case EBADOP:
			{
				return ErrorCode::BADOP_ERROR;
			}
			case EBADID:
			{
				return ErrorCode::BADID_ERROR;
			}
			case EEXISTS:
			{
				return ErrorCode::EXISTS_ERROR;
			}
			case ENOUSER:
			{
				return ErrorCode::NOUSER_ERROR;
			}
			default:
			{
				return ErrorCode::NO_ERROR;
			}
		}
	}

	static inline const std::string TFTPErrorCodeToString(const uint16_t err_code)
	{
		switch(err_code)
		{
			case EUNDEF:
			{
				return {"Not defined, or generic error"};
			}
			case ENOTFOUND:
			{
				return {"File not found"};
			}
			case EACCESS:
			{
				return {"Access violation"};
			}
			case ENOSPACE:
			{
				return {"No disk space, or allocation failure"};
			}
			case EBADOP:
			{
				return {"Illegal TFTP operation"};
			}
			case EBADID:
			{
				return "Unknown transfer ID";
			}
			case EEXISTS:
			{
				return {"File already exists"};
			}
			case ENOUSER:
			{
				return {"No such user"};
			}
			default:
			{
				return {"Unknown or undefined error"};
			}
		}
	}

	constexpr uint8_t TFTP_DEFAULT_PORT{69};
	const std::string TFTP_MODE_NETASCII = "octet";
	const size_t TFTP_MAX_ALLOWED_RQ_WQ_PATH_SIZE{
		(SEGSIZE - ((TFTP_MODE_NETASCII.length() - 1) - 1) - (sizeof(tftphdr) - sizeof(tftphdr::th_u1)))
	};
	const size_t TFTP_MODE_SECTION_SIZE{TFTP_MODE_NETASCII.size() + 1};
	constexpr uint8_t TFTP_RWA_HEADER_SIZE{sizeof(tftphdr::th_opcode) + sizeof(tftphdr::th_block)};
	constexpr uint16_t TFTP_MAX_WR_PAYLOAD_SIZE{(SEGSIZE - TFTP_RWA_HEADER_SIZE)};
}
