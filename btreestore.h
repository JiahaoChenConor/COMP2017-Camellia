#ifndef BTREESTORE_H
#define BTREESTORE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <string.h>

#define BYTES_ONE_BLOCK 8
#define MAXIMUM_BLOCKS 25000
#define two_power_32 0x100000000
#define ADDRESS 8


struct info {
    uint32_t size;
    uint32_t key[4];
    uint64_t nonce;
    void * data;
};

struct node {
    uint16_t num_keys;
    uint32_t * keys;
};

// Branching is b
// ⌈b/2⌉ ≤ n ≤ b for internal since leaf has no children, n is number of children 
//      for root, it is a leaf, it obeys n ≤ b. If it is not a leaf, it obeys 2 ≤ n ≤ b 
// every node has n - 1 keys

struct Btree_Node {
    uint16_t num_children;
    uint16_t num_keys;
    uint32_t * keys;                // one key is corresponds to one node_info
    struct info ** keys_info;       // *key_info is an array of pointers, each pointer ponits to a strcut info
    struct Btree_Node ** children;  // *children is an array of pointers, each poniter ponits to a Btree_Node 
    struct Btree_Node * parent;

};

typedef struct Btree_Node Btree_Node;


typedef struct encrypt_or_decrypt_info {
    uint64_t * plain;
    uint32_t key[4];
    uint64_t nonce;
    uint64_t * cipher;
    uint32_t start_block_index;
    uint32_t end_block_index;
}INFO;


// ####### Main functions for B_tree ########

void * init_store(uint16_t branching, uint8_t n_processors);

void close_store(void * helper);

int btree_insert(uint32_t key, void * plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void * helper);

int btree_retrieve(uint32_t key, struct info * found, void * helper);

int btree_decrypt(uint32_t key, void * output, void * helper);

int btree_delete(uint32_t key, void * helper);

uint64_t btree_export(void * helper, struct node ** list);

void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4]);

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4]);

void encrypt_tea_ctr(uint64_t * plain, uint32_t key[4], uint64_t nonce, uint64_t * cipher, uint32_t num_blocks);

void decrypt_tea_ctr(uint64_t * cipher, uint32_t key[4], uint64_t nonce, uint64_t * plain, uint32_t num_blocks);


// ######## Some helpful functions ############
void lock_at_start();

void free_one_node(Btree_Node ** node);

void free_all(Btree_Node* root);

int find_position_of_child(Btree_Node* parent, Btree_Node* child, uint16_t* p);

int find_position_of_key(Btree_Node* node, uint32_t key, uint16_t* p);

int find_position_of_key_info(Btree_Node* node, struct info* key_info, uint16_t* p);

Btree_Node* initialize_Btree_node(uint16_t branching, void *memory_start);

void delete_one_node(Btree_Node **node, void * helper);

Btree_Node * find_insert_node(uint32_t key, Btree_Node * root);

int add_key_in_one_node(Btree_Node * node, uint32_t key, struct info* key_info_ptr);

int delete_key_in_one_node(Btree_Node * node, uint32_t key, int free_key_info);

int need_split(Btree_Node* node, uint16_t branching);

void add_children(Btree_Node * left_child, Btree_Node * right_child, Btree_Node * original_child, Btree_Node * parent);

void splitNode(Btree_Node* node, uint16_t branching, void *helper);

Btree_Node* recursive_find(uint32_t target_key, struct info * found, Btree_Node * root);

void find_maximum_node(Btree_Node* root, Btree_Node** res, uint32_t* maximum_key);

void swap_key(uint32_t key1, Btree_Node* node1, uint32_t key2, Btree_Node* node2);

void replace_key(Btree_Node* node_replaced, uint32_t key_replaced, Btree_Node* node, u_int32_t key);

void merge_two_nodes(Btree_Node* target, Btree_Node* node_be_merged, void *helper);

void move_child(Btree_Node * dest_node, Btree_Node *child, Btree_Node * original_node, int leftmost_or_rightmost);

void balance_internal(Btree_Node *internal_node, int min_key_num, Btree_Node* last_child, void* helper);

void preorder(Btree_Node * root, struct node *list, int num_nodes);

void * thread_encrypt_tea_ctr(void * argv);

void * thread_decrypt_tea_ctr(void * argv);







#endif
