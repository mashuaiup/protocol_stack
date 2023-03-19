#ifndef __protostack__
#define __protostack__

#define LADD(item, list) do { \
    item->next = list; \
    item->pre = NULL; \
    if(list != NULL) list->pre = item; \
    list = item; \
}while(0);

#endif