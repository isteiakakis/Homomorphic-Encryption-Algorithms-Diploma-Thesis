#include "socket_io.h"
#include <cstdio>
#include <cstddef>
#include <unistd.h>

using namespace std;

ssize_t read_all(int fd, void *buf, size_t size)
{
    size_t bytes_read = 0;
    while (bytes_read < size) {
        ssize_t result = read(fd, reinterpret_cast<byte*>(buf) + bytes_read, size - bytes_read);
        if (result < 0) {
            // Handle read error
            perror("read");
            return -1;
        }
        if (result == 0) {
            // EOF
            break;
        }
        bytes_read += result;
    }
    return bytes_read;
}

ssize_t write_all(int fd, const void *buf, size_t size)
{
    size_t bytes_writen = 0;
    while (bytes_writen < size) {
        ssize_t result = write(fd, reinterpret_cast<const byte*>(buf) + bytes_writen, size - bytes_writen);
        if (result < 0) {
            // Handle write error
            perror("write");
            return -1;
        }
        bytes_writen += result;
    }
    return bytes_writen;
}
