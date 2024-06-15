/*
 * SocketWrapper.cpp
 *
 *  Created on: 9 de abr. de 2024
 *      Author: ianwillianb
 */

#include "SocketWrapper.h"
#include <sys/socket.h>
#include <unistd.h>

SocketWrapper::SocketWrapper(const int sock_namespace, const int sock_style, const int sock_protocol)
{
    fd = socket(sock_namespace, sock_style, sock_protocol);
}

SocketWrapper::SocketWrapper(const int file_descriptor)
{
    fd = file_descriptor;
}

bool SocketWrapper::IsValid()
{
    return fd >= 0;
}

SocketWrapper::~SocketWrapper()
{
    if(IsValid())
    {
        close(fd);
    }
}
