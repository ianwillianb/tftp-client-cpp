/*
 * SocketWrapper.h
 *
 *  Created on: 9 de abr. de 2024
 *      Author: ianwillianb
 */

#ifndef SOCKETWRAPPER_H_
#define SOCKETWRAPPER_H_

class SocketWrapper
{
    public:
        /**
         * @brief SocketWrapper Allocates a new socket, stores its file descriptor internally.
         * @param sock_namespace Socket namespace
         * @param sock_style Socket style
         * @param sock_protocol Socket protocol
         */
        SocketWrapper(const int sock_namespace, const int sock_style, const int sock_protocol);

        /**
         * @brief SocketWrapper Wraps an existing socket file descriptor.
         * @param file_descriptor The socket file descriptor.
         */
        SocketWrapper(const int file_descriptor);

        /**
         * @brief SocketWrapper move constructor
         * @param other SocketWrapper object
         */
        SocketWrapper(SocketWrapper&& other)
        {
            this->fd = other.fd;
            other.fd = -1;
        }

        /**
         * @brief SocketWrapper move assignment operator override
         * @param other SocketWrapper object
         * @return moved SocketWrapper object
         */
        SocketWrapper& operator=(SocketWrapper &&other)
        {
            this->fd = other.fd;
            other.fd = -1;
            return *this;
        }

        /* Delete copy constructor, sockets must not be shared */
        SocketWrapper(const SocketWrapper &other) = delete;
        SocketWrapper& operator=(const SocketWrapper &other) = delete;

        /* Test operators */

        /**
         * @brief IsValid Indicates if the object wraps a valid socket file descriptor
         * @return true if the object contains a valid socket file descriptor
         */
        bool IsValid();

        /**
         * @brief Overrides bool operator with IsValid method
         */
        operator bool()
        {
            return IsValid();
        }

        /**
         * @brief GetSocketFD Getter for wrapper socket file descriptor
         * @return Wrapped socket file descriptor
         */
        int GetSocketFD() const
        {
            return fd;
        }

        operator int()
        {
            return fd;
        }

       ~SocketWrapper();

    private:
        int fd{-1};
};

#endif /* SOCKETWRAPPER_H_ */
