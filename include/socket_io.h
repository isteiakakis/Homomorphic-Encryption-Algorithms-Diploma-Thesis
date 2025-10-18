#pragma once

#include <cstddef>
#include <unistd.h>

ssize_t read_all(int fd, void *buf, std::size_t size);

ssize_t write_all(int fd, const void *buf, std::size_t size);
