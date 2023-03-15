#include<stdio.h>
#include<rte_eal.h>
#include<rte_hash.h>
#include<rte_jhash.h>
#include <rte_ethdev.h>
#include<arpa/inet.h>
#define hash_size  50
// struct stream{
//     uint32_t sip;
//     uint32_t dip;
//     uint16_t sport;
//     uint16_t dport;
//     uint8_t proto;
// };

struct stream{  
    union{
        struct in_addr sip;
        struct in6_addr sip6;
    };
    union{
        struct in_addr dip;
        struct in6_addr dip6;
    };
    u_int16_t sport;
    u_int16_t dport;
    u_int8_t proto;
};

static void print_key(struct stream *key){
    char sip[18];
    char dip[18];
    inet_ntop(AF_INET,&(key->sip.s_addr),sip,sizeof(sip));
    inet_ntop(AF_INET,&(key->dip.s_addr),dip,sizeof(dip));
    printf("sip:%s\ndip:%s\nsport:%d\ndsport:%d\nproto:%d\n",sip,dip,key->sport,key->dport,key->proto);
}

static struct rte_hash * create_hash_table(const char * name){

    struct rte_hash_parameters *parms = (struct rte_hash_parameters *)malloc(sizeof(struct rte_hash_parameters));
    if(parms == NULL){
        return NULL;
    }  

    parms->name = name;
    parms->entries = hash_size;
    parms->reserved = 0;
    parms->key_len = 13;
    parms->hash_func = rte_jhash;
    parms->hash_func_init_val = 0;
    parms->socket_id = rte_socket_id();

    struct rte_hash * hash = rte_hash_create(parms);
    // free(parms);
    return hash;
    /*这边是不是需要进行parms内存的回收 
    */   
}
int main(int argc, char * argvs[]){
    rte_eal_init(argc,argvs);
    //创建hase table
    struct rte_hash *hash = create_hash_table("ms_hash");
    if(hash==NULL){
        printf("hash init error!\n");
    }
   
    //随机创建数据
    char ip[15];
    for(int i = 0; i < hash_size; i++){
        snprintf(ip, sizeof(ip), "192.168.66.%d", i);
        printf("ip地址为:%s\n", ip);
        struct stream *connect_stream  = (struct stream*)malloc(sizeof(struct stream));
        
        inet_pton(AF_INET,ip,&connect_stream->sip.s_addr);//sip
        inet_pton(AF_INET,ip,&connect_stream->dip.s_addr);//dip
        connect_stream->sport = i;
        connect_stream->dport = i;
        connect_stream->proto = i % 8;
        
        if(i % 4 == 0 ){  //只是插入key
            rte_hash_add_key(hash, connect_stream);
            printf("add key correct!\n");
        }
        else if(i % 4 == 1){//插入keydata
            hash_sig_t hash_value = rte_hash_hash(hash, connect_stream);
            rte_hash_add_key_with_hash(hash,connect_stream,hash_value);
            rte_hash_del_key(hash,connect_stream);
        }else if(i % 4 == 2){
            struct stream *node = (struct stream*)malloc(sizeof(struct stream));
            memcpy(node, connect_stream, sizeof(struct stream));
            rte_hash_add_key_data(hash, connect_stream, node);
            rte_hash_del_key(hash,connect_stream);
            // free(node);
        }else if(i % 4 == 3){
            hash_sig_t hash_value = rte_hash_hash(hash, connect_stream);
            struct stream *node = (struct stream*)malloc(sizeof(struct stream));
            memcpy(node, connect_stream, sizeof(struct stream));
            rte_hash_add_key_with_hash_data(hash, connect_stream, hash_value ,node);
            // free(node);
            rte_hash_del_key(hash,connect_stream);
        }else{
            
        }
        free(connect_stream);
    }
    //增加
    //删除
    //修改
    //查询
    struct connet_stream *key = NULL;
    void * value = NULL;
    uint32_t next = 0;
    while(rte_hash_iterate(hash, (const void **) &key, (void **) &value, (uint32_t *) &next) >= 0){
        printf("进入wile循环\n");
        // print_key((struct stream *)key);
        if(value != NULL){
            // printf("value 的值不为空,且目的端口号为%d\n",((struct stream *)value)->dport);
            print_key((struct stream *)value);
        }else{
            printf("value的值是为空的\n");
        }
        printf("%d\n",next);
        printf("\n");
    }
}


