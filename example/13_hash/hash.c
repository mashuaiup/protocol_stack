#include <stdio.h>
#include <rte_eal.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ethdev.h>

struct net_key {

	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	char proto;

};

static void print_key(struct net_key *key) {

	printf("sip: %x, dip: %x, sport: %x, dport: %x, proto: %d\n", 
		key->sip, key->dip, key->sport, key->dport, key->proto);

}

#define HASH_KEY_COUNT	16

static struct rte_hash *create_hash_table(const char *name) {

	struct rte_hash_parameters *params = (struct rte_hash_parameters*)malloc(sizeof(struct rte_hash_parameters));
	if (!params) return NULL;

	params->name = name;
	params->entries = 8192;
	params->key_len = sizeof(struct net_key);
	params->hash_func = rte_jhash;//布谷鸟哈希
	params->hash_func_init_val = 0;
	
	params->socket_id = rte_socket_id();

	struct rte_hash *hash = rte_hash_create(params);

	return hash;

}


int main(int argc, char *argv[]) {

	rte_eal_init(argc, argv);

// key
// key hash
// key data
// key hash, data

	struct rte_hash *hash = create_hash_table("hash table");
	
	int i = 0;
	for (i = 0;i < HASH_KEY_COUNT;i ++) {

		struct net_key *nk = malloc(sizeof(struct net_key));
		nk->sip = 0x11111111 + i;
		nk->dip = 0x22222222 + i;
		nk->sport = 0x3333 + i;
		nk->sport = 0x4444 + i;
		nk->proto = i % 2;

		if (i % 4 == 0) {
			rte_hash_add_key(hash, nk);
		} else if (i % 4 == 1) {

			hash_sig_t hash_value = rte_hash_hash(hash, nk);
			rte_hash_add_key_with_hash(hash, nk, hash_value);

		} else if (i % 4 == 2) {

			uint32_t *tmp = malloc(sizeof(uint32_t));
			*tmp = i;
			
			rte_hash_add_key_data(hash, nk, tmp); // <> --> tcb
		} else {
			hash_sig_t hash_value = rte_hash_hash(hash, nk);
			uint32_t *tmp = malloc(sizeof(uint32_t));
			*tmp = i;
			
			rte_hash_add_key_with_hash_data(hash, nk, hash_value, tmp);

		}

		
	}

	//ms:删除
	for (i = 0;i < HASH_KEY_COUNT;i ++) {

		struct net_key *nk = malloc(sizeof(struct net_key));
		nk->sip = 0x11111111 + i;
		nk->dip = 0x22222222 + i;
		nk->sport = 0x3333 + i;
		nk->sport = 0x4444 + i;
		nk->proto = i % 2;

		int idx = rte_hash_lookup(hash, nk);
		printf("hash lookup --> sip: %x, idx: %d\n", nk->sip, idx);

		rte_hash_del_key(hash, nk);
		free(nk);

	}	

	
	struct net_key *key = NULL;
	void *value = NULL;
	uint32_t next = 0;

	//ms:遍历
	while(rte_hash_iterate(hash, (const void **)&key, &value, &next) >= 0) {

		if (value != NULL) {
			printf("value: %d \t", *(uint32_t*)value);
			print_key(key);
		} else 
			print_key(key);
		
	}

}




