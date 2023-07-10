#include "std.h"
int set_fd_frombitmap(int fd, unsigned char* fd_table) {

	if (fd >= MAX_FD_COUNT) return -1;

	fd_table[fd/8] &= ~(0x1 << (fd % 8));

	return 0;
}

int get_fd_frombitmap(unsigned char* fd_table) {

	int fd = DEFAULT_FD_NUM;
	for ( ;fd < MAX_FD_COUNT;fd ++) {
		if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
			fd_table[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}
	return -1;
}