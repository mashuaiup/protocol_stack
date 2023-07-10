#ifndef __STD__
#define __STD__
#define DEFAULT_FD_NUM	               3
#define MAX_FD_COUNT	               1024

#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)


#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)

int set_fd_frombitmap(int fd, unsigned char* fd_table);
int get_fd_frombitmap(unsigned char* fd_table);
#endif
