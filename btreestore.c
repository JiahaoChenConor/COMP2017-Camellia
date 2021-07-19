#include "btreestore.h"
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


/*              
    Main idea:
            For the structure:
                1. The address of root is recorded in heap
                2. For every node   
                    + num_children;
                    + num_keys;
                    + uint32_t * keys
                    + struct info ** keys_info; (key_info is an array of pointers, each pointer ponits to a strcut info)
                    + struct Btree_Node ** children; (children is an array of pointers, each poniter ponits to a Btree_Node )
                    + struct Btree_Node * parent;
    
            For optimization speed: 
                1. Reduced variables so that memory load time is reduced. 
                2. Use threads to encrypt a certain number of blocks.
*/


void * init_store(uint16_t branching, uint8_t n_processors) {
    //                          branching , process, number of nodes, address of root node
    void* heapstart = malloc(sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint16_t) + ADDRESS);
    uint16_t * branch_ptr = (uint16_t *) heapstart;
    * branch_ptr = branching;
    uint8_t * processors_ptr = (u_int8_t *) (branch_ptr + 1);
    * processors_ptr = n_processors;

    // The num of nodes is 0
    // The pointer for the root is NULL;
    memset(processors_ptr + 1, '\0', sizeof(uint16_t) + ADDRESS);
    return heapstart;
}

void close_store(void * helper) {
    Btree_Node * root = *((Btree_Node **) (helper + 5));
    free_all(root);
    free(helper);
    helper = NULL;
    return;
}

int btree_insert(uint32_t key, void * plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void * helper) {

    lock_at_start();

    uint16_t branching = * ((uint16_t * ) helper);

    Btree_Node ** root_ptr = (Btree_Node **) (helper + 5);

    if (*root_ptr == NULL){
        *root_ptr = initialize_Btree_node(branching, NULL);
        uint16_t * num_nodes = (uint16_t *)(helper + 3); 
        *(num_nodes) += 1;
    }
    Btree_Node * root = *root_ptr;
    // First, follow the searching algorithm to search for K in the tree. 
    // It is an error if K already exists in the tree.
    // Identify the leaf node that would contain K
    struct info found;
    Btree_Node * find = recursive_find(key, &found, root);


    if (find != NULL){
        // if find one node successfully
        pthread_mutex_unlock(&lock);
        return 1;
    }

    Btree_Node * inserted_node = find_insert_node(key, root);

    // malloc space for one key_info
    struct info *new_key_info = (struct info *)malloc(sizeof(struct info));
 
    new_key_info -> size = count;
    memcpy(new_key_info -> key, encryption_key, sizeof(uint32_t) * 4); 
    new_key_info -> nonce = nonce;
    // count the number of blocks of plaintext
    // one block 8 bytes    

    int num_blocks = count / BYTES_ONE_BLOCK;
    if (count % BYTES_ONE_BLOCK != 0){
        num_blocks ++;
    }

    uint64_t* plain = (uint64_t*) malloc(num_blocks * 8);
    uint64_t* cipher = (uint64_t*) malloc(num_blocks * 8);

    memset(plain, '\0', num_blocks * 8);
    memcpy(plain, plaintext, count);

    encrypt_tea_ctr(plain, encryption_key, nonce, cipher, num_blocks);
    new_key_info -> data = (void*) cipher;
    
    add_key_in_one_node(inserted_node, key, new_key_info);

    free(plain);
  
    plain = NULL;
  
   
    splitNode(inserted_node, branching, helper);

    pthread_mutex_unlock(&lock);
    
    return 0;
}


int btree_retrieve(uint32_t key, struct info * found, void * helper) {
   
    // After 3 bytes there is the root 
    Btree_Node * root = *((Btree_Node **) (helper + 5));

    Btree_Node * res = recursive_find(key, found, root);
    if (res == NULL){
        
        return 1;
    }else{ 
        
        return 0;
    }

}


int btree_decrypt(uint32_t key, void * output, void * helper) {
    
    struct info found_info;
    Btree_Node * root = *((Btree_Node **) (helper + 5));
    Btree_Node * node = recursive_find(key, &found_info, root);
    if (node == NULL){
        pthread_mutex_unlock(&lock);
        return 1;
    }

    int num_blocks = found_info.size / BYTES_ONE_BLOCK;
    if (found_info.size % BYTES_ONE_BLOCK != 0){
        num_blocks ++;
    }

    uint64_t* plain = (uint64_t*) malloc(num_blocks * 8);
    uint64_t* cipher = (uint64_t*) malloc(num_blocks * 8);
    memset(plain, 0, num_blocks * 8);
    memset(cipher, 0, num_blocks * 8);

    memcpy(cipher, found_info.data, num_blocks * 8);

    decrypt_tea_ctr(cipher, found_info.key, found_info.nonce, plain, num_blocks);
    memcpy(output, plain, found_info.size);
    free(plain);
    free(cipher);
    plain = NULL;
    cipher = NULL;
    
    return 0;
}

int btree_delete(uint32_t key, void * helper) {
    lock_at_start();
    uint16_t branching = * ((uint16_t * ) helper);
    Btree_Node * root = *((Btree_Node **) (helper + 5));
    Btree_Node * target;

    // Step 1: check K exists
    struct info found;;
    Btree_Node* node_contains_key = recursive_find(key, &found, root);
    if (node_contains_key == NULL){
        pthread_mutex_unlock(&lock);
        return 1;
    }

    if (node_contains_key == root && root->num_children == 0){
        delete_key_in_one_node(node_contains_key, key, 1);
         pthread_mutex_unlock(&lock);
        return 0;
    }


    //If K is in a leaf node, just delete the K
    if (node_contains_key -> num_children == 0){
        target = node_contains_key;
     
    }
    // If K is in a internal node, swap it with the maximum key in its left tree (root is the left childnode K separates)
    else{
        Btree_Node *node_contains_maximum_key;
        uint32_t maximum_key = 0;
        
        uint16_t position = 0;
        find_position_of_key(node_contains_key, key, &position);

        Btree_Node *left_child = *(node_contains_key -> children + position);
        find_maximum_node(left_child, &node_contains_maximum_key, &maximum_key);

        // Then we find the node which contains the maximum_key
        // Then swap keys
        swap_key(key, node_contains_key, maximum_key, node_contains_maximum_key);   
        
        target = node_contains_maximum_key;  
    }



    // Target is updated which must be a leaf node at this stage

    // After delete, if there are no keys in the leaf node anymore, do not free the node
    // Even if the keys in leaf node is 0, some keys will be added, or merge

    int num_keys = delete_key_in_one_node(target, key, 1);
    
    // every node has n-1 keys, n is their children , n is >= b/2 round up, so n - 1 >= b/2 - 1. round up
    int min_key_num = branching/2 - 1;
    if (branching % 2 != 0){
        min_key_num++;
    }

    // After delete the key, if the num_keys >= min_key_num. END OF DELETE
    if (num_keys >= min_key_num){
        pthread_mutex_unlock(&lock);
        return 0;
    }

    // After deletion, the leaf node has less than min_key_num

    // If the node is leftmost then it only has parent right key, and only need to find right sibling
    // If the node is rightmost then it only has parent left key, and only need to find left sibling
    uint32_t parent_key_left = 0;
    uint32_t parent_key_right = 0;
    struct info* parent_key_info_left = NULL;
    struct info* parent_key_info_right = NULL;
    Btree_Node* left_sibling = NULL;
    Btree_Node* right_sibling = NULL;
    
    
    uint16_t position = 0;
    find_position_of_child(target->parent, target, &position);
    
    /* case 1, no left sibling
    how about in parent only one key
             {4}
            /    \
           /      \
         {3}   {5, 10}
     1. delete 3
             {4}
            /    \
           /      \
         {}    {5, 10}
    separates by left_key = NULL, right_key = 4
    only has right sibling {5, 10}, smallest is 5, replace 4 with 5, and put 4 into its left_child
             {5}
            /    \
           /      \
         {4}    {10}
    */
    if (position == 0){
        
        // check the right sibling
        right_sibling = *(target->parent->children + 1);
        // The first key in parent is its right key
        parent_key_right = *(target->parent->keys);
        parent_key_info_right = *(target->parent->keys_info);
        
        if (right_sibling->num_keys > min_key_num){
            // Correct order should be
            // 1. add the key and key_info from parent into target node
            // 2. replace the key and key_info in parent with the smallest key in right sibling 
            // 3. delete the key and key_info pointer from right sibling not free them.

            add_key_in_one_node(target, parent_key_right, parent_key_info_right);
            // add the smallest key in to parent, and delete it from the original node
            uint32_t smallest_key = *(right_sibling -> keys + 0);
            replace_key(target->parent, parent_key_right, right_sibling, smallest_key);
            delete_key_in_one_node(right_sibling, smallest_key, 0);
        }

        
        else{
            /*  
                    b = 5, min_key_num = ceil(5/2) - 1 = 2  
                    inserted order: 1-8
                     {3, 6}
                    /   |   \ 
                   /    |    \
                  {1,2}{4,5} {7,8}

                  delete 2
                    {3, 6}
                    /   |   \ 
                   /    |    \
                  {1} {4,5} {7,8}

                  merge right  move 3 to it
                      {6}
                    /      \ 
                   /        \
                  {1,3,4,5}  {7,8}

            */
     
            // move all keys in immediate sibling to target node,

            merge_two_nodes(target, right_sibling, helper);
            // move the key in parent separates them into it, that key is parent_key_left
            add_key_in_one_node(target, parent_key_right, parent_key_info_right);
            // delete it from parent node, not free the key info
            delete_key_in_one_node(target->parent, parent_key_right, 0);

            // After this step, there will be internal nodes
            balance_internal(target->parent, min_key_num, target, helper);
        }

    }
    /* no right sibling
    how about in parent only one key
             {3}
            /    \
           /      \
         {1, 2}  {4}
     1. delete 4
             {3}
            /    \
           /      \
         {1, 2}    { }
    separates by left_key = 5, right_key = NULL
    only has left sibling {1, 2}, largest is 2, replace 5 with 2, abd put 5 into its right_child
             {2}
            /    \
           /      \
         {1}      {3}
    */
    else if (position == target->parent->num_keys){
        
        left_sibling = *(target->parent->children + position - 1);

        // The last key in its parent is its left parent key
        parent_key_left = *(target->parent->keys + position - 1);
        parent_key_info_left = *(target->parent->keys_info + position - 1);

        if (left_sibling->num_keys > min_key_num){
            add_key_in_one_node(target, parent_key_left, parent_key_info_left);
            uint32_t largest_key = *(left_sibling -> keys + left_sibling->num_keys - 1);
            replace_key(target->parent, parent_key_left, left_sibling, largest_key);
            delete_key_in_one_node(left_sibling, largest_key, 0);
        }

        
        else{
       
            // move all keys in immediate sibling to target node,
            merge_two_nodes(target, left_sibling, helper);
            //  move the key in parent separates them into it, that key is parent_key_left
            add_key_in_one_node(target, parent_key_left, parent_key_info_left);
            // delete it from parent node, not free the key info
            delete_key_in_one_node(target->parent, parent_key_left, 0);

            // After this step, there will be internal nodes
           
            balance_internal(target->parent, min_key_num, target, helper);
            
        }

    }else{

        /* If num_keys < min_key_num, b = 4, so min_key_num = 4/2 - 1 = 1
           inserted order:3,5,6,9,10,4
                {5, 9}
                /  |  \
               /   |   \
             {3,4} {6} {10}
         1. delete 6
                {5, 9}
                /  |  \
               /   |   \
             {3,4} {} {10}
            target node is separates by key_left = 5, key_right = 9 in parent node
            check exits immediate left sibling => {3, 4}, check it has more than min_key_num node, YES
            if it does, in parent {5, 9}, replace, key_left = 5, with largest key in left_child:4 and delete the key in child
            move key_left into target
                {4, 9}
                /  |  \
               /   |   \
             {3}  {5} {10}
        ########################
                {5, 9}
                /  |  \
               /   |   \
             {3}  {6} {10,11}
         1. delete 6
                {5, 9}
                /  |  \
               /   |   \
             {3}  {} {10,11}
             check exits immediate left sibling => {3}, check it has more than min_key_num node, NO
             check exits immediate right sibling => {10, 11}, check it has more than min_key_num, YES
             in parent{5, 9}, replace key_right = 9 with smallest key in right_child: 10, move 9 into target
                {5, 10}
                /  |  \
               /   |   \
             {3}  {9} {11}   
        */  
        left_sibling = *(target->parent->children + position - 1);
        parent_key_left = *(target->parent->keys + position - 1);
        parent_key_info_left = *(target->parent->keys_info + position - 1);

        right_sibling = *(target->parent->children + position + 1);
        parent_key_right = *(target->parent->keys + position);
        parent_key_info_right = *(target->parent->keys_info + position);

        if (left_sibling->num_keys > min_key_num){
            add_key_in_one_node(target, parent_key_left, parent_key_info_left);
            uint32_t largest_key = *(left_sibling -> keys + left_sibling->num_keys - 1);
            replace_key(target->parent, parent_key_left, left_sibling, largest_key);
            delete_key_in_one_node(left_sibling, largest_key, 0);
        }else if (right_sibling->num_keys > min_key_num){
            add_key_in_one_node(target, parent_key_right, parent_key_info_right);
            uint32_t smallest_key = *(right_sibling -> keys + 0);
            replace_key(target->parent, parent_key_right, right_sibling, smallest_key);
            delete_key_in_one_node(right_sibling, smallest_key, 0);
        }
        // no immediate sibling of the target node has more than the minimum number of keys, merge the target node with immediate sibling (left first )
        
        
        else{
            /*  
                    b = 5, min_key_num = ceil(5/2) - 1 = 2  
                    inserted order: 1-8
                     {3, 6}
                    /   |   \ 
                   /    |    \
                  {1,2}{4,5} {7,8}

                  delete 4
                        {6}
                       |   \ 
                       |    \
                {1,2,3,5}  {7,8}

            */
            // move all keys in immediate sibling to target node,
            merge_two_nodes(target, left_sibling, helper);
            //  move the key in parent separates them into it, that key is parent_key_left
            add_key_in_one_node(target, parent_key_left, parent_key_info_left);
            // delete it from parent node, not free the key info
            delete_key_in_one_node(target->parent, parent_key_left, 0);

            // After this step, there will be internal nodes
            balance_internal(target->parent, min_key_num, target, helper);
        }


    }
    pthread_mutex_unlock(&lock);
    return 0;
}



void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4]) {
    //  little endian
    int sum = 0;
    int delta = 0x9E3779B9;
    cipher[0] = plain[0];
    cipher[1] = plain[1];

    for (int i = 0; i < 1024; i++){
        sum = (sum + delta) % two_power_32;
        int tmp1 = ((cipher[1] << 4) + key[0]) % two_power_32;
        int tmp2 = (cipher[1] + sum) % two_power_32;
        int tmp3 = ((cipher[1] >> 5) + key[1]) % two_power_32;
        cipher[0] = (cipher[0] + (tmp1 ^ tmp2 ^ tmp3)) % two_power_32;
        int tmp4 = ((cipher[0] << 4) + key[2]) % two_power_32;
        int tmp5 = (cipher[0] + sum) % two_power_32;
        int tmp6 = ((cipher[0] >> 5) + key[3]) % two_power_32;
        cipher[1] = (cipher[1] + (tmp4 ^ tmp5 ^ tmp6)) % two_power_32;
    }
 
    return;
}

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4]) {
    //  little endian
    uint32_t sum = 0xDDE6E400;
    uint32_t delta = 0x9E3779B9;

    for (int i = 0; i < 1024; i++){
        uint32_t tmp4 = ((cipher[0] << 4) + key[2]) % two_power_32;
        uint32_t tmp5 = (cipher[0] + sum) % two_power_32;
        uint32_t tmp6 = ((cipher[0] >> 5) + key[3]) % two_power_32;
        cipher[1] = (cipher[1] - (tmp4 ^ tmp5 ^ tmp6)) % two_power_32;
        uint32_t tmp1 = ((cipher[1] << 4) + key[0]) % two_power_32;
        uint32_t tmp2 = (cipher[1] + sum) % two_power_32;
        uint32_t tmp3 = ((cipher[1] >> 5) + key[1]) % two_power_32;
        cipher[0] = (cipher[0] - (tmp1 ^ tmp2 ^ tmp3)) % two_power_32;
        sum = (sum - delta) % two_power_32;
    }

    plain[0] = cipher[0];
    plain[1] = cipher[1];
    

    return;
}


uint64_t btree_export(void * helper, struct node ** list) {
    lock_at_start();
    uint16_t num_nodes = *((uint16_t *)(helper + 3)); 
    Btree_Node * root = *((Btree_Node **) (helper + 5));
    if(num_nodes == 0){
        return 0;
    }
    
    *list = (struct node *) malloc(num_nodes * sizeof(struct node));
    for (int i = 0 ; i < num_nodes; i++){
        (*list + i) -> num_keys = 0;
    }

    preorder(root, *list, num_nodes);
    pthread_mutex_unlock(&lock);
    return num_nodes;
}




void * thread_encrypt_tea_ctr(void * argv){
    INFO *info = (INFO *) argv;
    int delta = 0x9E3779B9;
    for (uint32_t i = info->start_block_index; i < info->end_block_index; i++){
        uint64_t tmp = i ^ info->nonce;
    
        uint32_t * tmp_ptr = (uint32_t *) (&tmp);  

        int sum = 0;
        // Reduce the memory load
        for (int j = 0; j < 1024; j++){
            sum = (sum + delta) % two_power_32;
            (*(tmp_ptr)) = (
                (*(tmp_ptr)) + 
                (
                    ((((*(tmp_ptr + 1)) << 4) + info->key[0]) % two_power_32) ^ 
                    (((*(tmp_ptr + 1)) + sum) % two_power_32) ^ 
                    ((((*(tmp_ptr + 1)) >> 5) + info->key[1]) % two_power_32)
                )
            ) % two_power_32;


            (*(tmp_ptr + 1)) = (
                (*(tmp_ptr + 1)) + 
                (
                    ((((*(tmp_ptr)) << 4) + info->key[2]) % two_power_32) ^ 
                    (((*(tmp_ptr)) + sum) % two_power_32) ^ 
                    ((((*(tmp_ptr)) >> 5) + info->key[3]) % two_power_32)
                )
            ) 
            % two_power_32;
        }
        *(info->cipher + i) = *(info->plain + i) ^ (*(tmp_ptr) + (((uint64_t) *(tmp_ptr + 1)) << 32));
    }
    return NULL;

}

void * thread_decrypt_tea_ctr(void * argv){
    INFO *info = (INFO *) argv;
    int delta = 0x9E3779B9;
    for (uint32_t i = info->start_block_index; i < info->end_block_index; i++){
        uint64_t tmp = i ^ info->nonce;
    
        uint32_t * tmp_ptr = (uint32_t *) (&tmp);  

        int sum = 0;
        
        for (int j = 0; j < 1024; j++){
            sum = (sum + delta) % two_power_32;
            (*(tmp_ptr)) = (
                (*(tmp_ptr)) + 
                (
                    ((((*(tmp_ptr + 1)) << 4) + info->key[0]) % two_power_32) ^ 
                    (((*(tmp_ptr + 1)) + sum) % two_power_32) ^ 
                    ((((*(tmp_ptr + 1)) >> 5) + info->key[1]) % two_power_32)
                )
            ) % two_power_32;


            (*(tmp_ptr + 1)) = (
                (*(tmp_ptr + 1)) + 
                (
                    ((((*(tmp_ptr)) << 4) + info->key[2]) % two_power_32) ^ 
                    (((*(tmp_ptr)) + sum) % two_power_32) ^ 
                    ((((*(tmp_ptr)) >> 5) + info->key[3]) % two_power_32)
                )
            ) 
            % two_power_32;
        }
        *(info->plain + i) = *(info->cipher + i) ^ (*(tmp_ptr) + (((uint64_t) *(tmp_ptr + 1)) << 32));
    }
    return NULL;

}


void encrypt_tea_ctr(uint64_t * plain, uint32_t key[4], uint64_t nonce, uint64_t * cipher, uint32_t num_blocks) {
    // if the length of plaintext is 65, and it has 65/8 = 8 ......1 , we need to padding the rest 1 byte with 7 bytes
    // but we can not access the 7 bytes after plain text

    int delta = 0x9E3779B9;

    // Step1: calculate the thread need
    uint32_t num_of_threads = num_blocks / MAXIMUM_BLOCKS;
    if (num_blocks % MAXIMUM_BLOCKS != 0){
        num_of_threads ++;
    }

    if (num_of_threads == 1){
        for (uint32_t i = 0; i < num_blocks; i++){
            uint64_t tmp = i ^ nonce;
        
            // change tmp1 (64 bits) into tmp1_array[2] which is (32bit each)
            // change tmp2 (64 bits) into tmp2_array[2] which is (32bit each)
            uint32_t * tmp_ptr = (uint32_t *) (&tmp);  // lower = tmp1_ptr + 1, array[0].  higher = tmp1_ptr, array[1]
            int sum = 0;
            
            for (int j = 0; j < 1024; j++){
                sum = (sum + delta) % two_power_32;
                (*(tmp_ptr)) = (
                    (*(tmp_ptr)) + 
                    (
                        ((((*(tmp_ptr + 1)) << 4) + key[0]) % two_power_32) ^ 
                        (((*(tmp_ptr + 1)) + sum) % two_power_32) ^ 
                        ((((*(tmp_ptr + 1)) >> 5) + key[1]) % two_power_32)
                    )
                ) % two_power_32;


                (*(tmp_ptr + 1)) = (
                    (*(tmp_ptr + 1)) + 
                    (
                        ((((*(tmp_ptr)) << 4) + key[2]) % two_power_32) ^ 
                        (((*(tmp_ptr)) + sum) % two_power_32) ^ 
                        ((((*(tmp_ptr)) >> 5) + key[3]) % two_power_32)
                    )
                ) 
                % two_power_32;
            }
            *(cipher + i) = *(plain + i) ^ (*(tmp_ptr) + (((uint64_t) *(tmp_ptr + 1)) << 32));
        }
    }else{
        pthread_t* thread_ID = (pthread_t *) malloc(num_of_threads * sizeof(pthread_t));
        INFO** pointers = (INFO**) malloc(num_of_threads * 8);

        for (uint32_t i = 0; i < num_of_threads; i++){
            INFO *info = malloc(sizeof(INFO));
            info -> plain = plain;
            memcpy(info -> key, key, sizeof(uint32_t) * 4);
            info -> nonce = nonce;
            info -> cipher = cipher;
            *(pointers + i) = info;
            info -> start_block_index = i * MAXIMUM_BLOCKS;
            if (i != num_of_threads - 1){
                
                info -> end_block_index = (i+1) * MAXIMUM_BLOCKS;
                pthread_create(thread_ID + i, NULL, &thread_encrypt_tea_ctr, (void*) (info));
            }else{
                info -> end_block_index = num_blocks;
                pthread_create(thread_ID + i, NULL, &thread_encrypt_tea_ctr, (void*) (info));
            }
        }

        for (uint32_t i = 0; i < num_of_threads; i++){
            pthread_join(*(thread_ID + i), NULL);
        }
        for (uint32_t i = 0; i < num_of_threads; i++){
            free (*(pointers + i));
        }
        free(pointers);
        free(thread_ID);
        thread_ID = NULL;
    }
    

    return;
}



void decrypt_tea_ctr(uint64_t * cipher, uint32_t key[4], uint64_t nonce, uint64_t * plain, uint32_t num_blocks) {
    //// plain = cipher ^ encrypt(i ^ nonce)
    uint32_t num_of_threads = num_blocks / MAXIMUM_BLOCKS;
    if (num_blocks % MAXIMUM_BLOCKS != 0){
        num_of_threads ++;
    }

    int delta = 0x9E3779B9;

    if (num_of_threads == 1){
        for (uint32_t i = 0; i < num_blocks; i++){
            uint64_t tmp = i ^ nonce;
        
            uint32_t * tmp_ptr = (uint32_t *) (&tmp); 
            
            int sum = 0;
            
            for (int j = 0; j < 1024; j++){
                sum = (sum + delta) % two_power_32;
                (*(tmp_ptr)) = (
                    (*(tmp_ptr)) + 
                    (
                        ((((*(tmp_ptr + 1)) << 4) + key[0]) % two_power_32) ^ 
                        (((*(tmp_ptr + 1)) + sum) % two_power_32) ^ 
                        ((((*(tmp_ptr + 1)) >> 5) + key[1]) % two_power_32)
                    )
                ) % two_power_32;


                (*(tmp_ptr + 1)) = (
                    (*(tmp_ptr + 1)) + 
                    (
                        ((((*(tmp_ptr)) << 4) + key[2]) % two_power_32) ^ 
                        (((*(tmp_ptr)) + sum) % two_power_32) ^ 
                        ((((*(tmp_ptr)) >> 5) + key[3]) % two_power_32)
                    )
                ) 
                % two_power_32;
            }


            *(plain + i) = *(cipher + i) ^ (*(tmp_ptr) + (((uint64_t) *(tmp_ptr + 1)) << 32));
        }

    }else{
        pthread_t* thread_ID = (pthread_t *) malloc(num_of_threads * sizeof(pthread_t));
        INFO** pointers = (INFO**) malloc(num_of_threads * 8);

        for (uint32_t i = 0; i < num_of_threads; i++){
            INFO *info = malloc(sizeof(INFO));
            info -> plain = plain;
            memcpy(info -> key, key, sizeof(uint32_t) * 4);
            info -> nonce = nonce;
            info -> cipher = cipher;
            *(pointers + i) = info;
            info -> start_block_index = i * MAXIMUM_BLOCKS;
            if (i != num_of_threads - 1){
                
                info -> end_block_index = (i+1) * MAXIMUM_BLOCKS;
                pthread_create(thread_ID + i, NULL, &thread_decrypt_tea_ctr, (void*) (info));
            }else{
                info -> end_block_index = num_blocks;
                pthread_create(thread_ID + i, NULL, &thread_decrypt_tea_ctr, (void*) (info));
            }
        }

        for (uint32_t i = 0; i < num_of_threads; i++){
            pthread_join(*(thread_ID + i), NULL);
        }
        for (uint32_t i = 0; i < num_of_threads; i++){
            free (*(pointers + i));
        }
        free(pointers);
        free(thread_ID);
        thread_ID = NULL;

    }

    return;
}



void lock_at_start(){
    pthread_mutex_lock(&lock);
}

void free_one_node(Btree_Node ** node){
    Btree_Node * node_ptr = *node;
    uint16_t num_keys = node_ptr -> num_keys;

    // free the data pointer in keys info firstly
    for (uint16_t i = 0; i < num_keys; i++){
        free((*(node_ptr->keys_info + i)) -> data);
        free(*(node_ptr->keys_info + i));
    }
    
    free(node_ptr->keys);
    free(node_ptr->keys_info);
    free(node_ptr->children);
    free(node_ptr);
    *node = NULL;
}

void free_all(Btree_Node* root){
    Btree_Node* cur = root;
    if (cur == NULL){
        return;
    }

    for (uint16_t i = 0; i < cur -> num_children; i++){
        Btree_Node* child = *(cur->children + i);
        free_all(child);
    }
    free_one_node(&cur);
}

int find_position_of_child(Btree_Node* parent, Btree_Node* child, uint16_t* p){
    Btree_Node ** children_address_ptr = parent->children;
    uint32_t position = 0;
    int exist = 0;
    for (;  position < (parent->num_children); position++){
        if (*(children_address_ptr + position) == child){
            exist = 1;
            *p = position;
            break;
        }
    }
    if (exist == 0){
        return -1;
    }

    return 0;
}

int find_position_of_key(Btree_Node* node, uint32_t key, uint16_t* p){
    uint32_t position = 0;
    int exist = 0;
    for (; position < node->num_keys; position++){
        if (*(node->keys + position) == key){
            exist = 1;
            *p = position;
            break;
        }
    }
    if (exist == 0){
        return -1;
    }

    return 0;
}

int find_position_of_key_info(Btree_Node* node, struct info* key_info, uint16_t* p){
    
    uint32_t position = 0;
    int exist = 0;
    for (; position < node->num_keys; position++){
        if (*(node->keys_info + position) == key_info){
            *p = position;
            exist = 1;
            break;
        }
    }
    if (exist == 0){
        return -1;
    }

    return 0;
}



Btree_Node* initialize_Btree_node(uint16_t branching, void *memory_start){
    Btree_Node * new_node;
    if (memory_start == NULL){
        new_node = (Btree_Node *) malloc(sizeof(Btree_Node));
    }else{
        new_node = (Btree_Node *) memory_start;
    }

    new_node -> num_keys = 0;
    new_node -> num_children = 0;
    new_node -> keys = (uint32_t *) malloc(sizeof(uint32_t) * branching);
    new_node -> keys_info = (struct info **) malloc(8 * branching);
    new_node -> children = (struct Btree_Node **) malloc(8 * (branching + 1));
    new_node -> parent = NULL;

    memset(new_node -> keys, '\0', sizeof(uint32_t) * branching);
    memset(new_node -> keys_info, '\0', 8 * branching);
    memset(new_node -> children, '\0', 8 * (branching + 1));

    return new_node;
}







// This will not free the data and data info
void delete_one_node(Btree_Node **node, void * helper){

    // change the children in parent
    Btree_Node* parent = (*node) -> parent;
 
    // search this node

    uint16_t position = 0;
    find_position_of_child(parent, *node, &position);


    // Num keys = 3
    //        k0          k1          k2
    //   c0         c1          c2          c3

    //   c0         c1          c3           

    //   c2 is deleted, so we should move all children after it one position ahead.
    //   remember to make the last position into NULL since it has been free_one_node

    *(parent -> children + position) = NULL;
    for (; position < parent->num_children; position++){
        *(parent->children + position) = *(parent->children + position + 1);
    }

    // since there are no keys in this node, just free it
    free((*node)->keys);

    free((*node)->keys_info);

    free((*node)->children);
    
    free((*node));
    *node = NULL;

    uint16_t * num_nodes = (uint16_t *)(helper + 3); 
    (*num_nodes) -= 1;
    parent->num_children -= 1;
}

Btree_Node * find_insert_node(uint32_t key, Btree_Node * root){
    Btree_Node * cur = root;
    // reach the leaf
    if ((cur -> num_children) == 0){
        return cur;
    }

    for (int i = 0; i < cur -> num_keys; i++){
        if (key < *(cur -> keys + i)){
            return find_insert_node(key, *(cur -> children + i));
        }

        if (i == cur -> num_keys - 1 && key > *(cur -> keys + i)){
            return find_insert_node(key, *(cur -> children + i + 1));
        }
    }

    return NULL;
}


int add_key_in_one_node(Btree_Node * node, uint32_t key, struct info* key_info_ptr){
    int num_keys = node -> num_keys;
    // search the position for the new key
    uint16_t position = 0;
    for (;position < num_keys ; position++){
        uint32_t original_key = *(node -> keys + position);
        if (key < original_key){
            break;
        }
    }

    // move the key backward
    // move the keys_info backward
    for (int i = num_keys - 1; i >= position; i--){
        *(node -> keys + i + 1) = *(node -> keys + i);
    }
    for (int i = num_keys - 1; i >= position; i--){
        *(node -> keys_info + i + 1) = *(node -> keys_info + i);
    }

    *(node -> keys + position) = key;
    *(node -> keys_info + position) = key_info_ptr;

    (node -> num_keys) += 1;
    return 1;
}


// return the remaining key numbers in this node
// if no such key, return -1
int delete_key_in_one_node(Btree_Node * node, uint32_t key, int free_key_info){
    // case 1, we delete the key that need to be delete, free data and keys_info
    // case 2, we delete the key in one node and move it to another, no need to free
    uint16_t num_keys = node -> num_keys;
   
    uint16_t position = 0;
    int find = find_position_of_key(node, key, &position);
 
    if (find == -1){
        return -1;
    }

    // num_of_keys = 4
    // K0    K1     K2    K3
    // delete(k1) index = 1
    
    // move the keys ahead from the position deleted.
    // K0    K2     K3    K3
    for (uint16_t i = position; i < num_keys - 1 ; i++){
        *(node -> keys + i) = *(node -> keys + i + 1);
    }

    // set the original last key into 0
    // K0    K2     K3     0
    *(node -> keys + num_keys - 1) = 0;

    struct info * removed_key_info = *(node -> keys_info + position);
    // Before move the keys_info, we need to record the key_info, since we need to free it
    // Move the keys_info ahead
    for (uint16_t i = position; i < num_keys - 1; i++){
        *(node -> keys_info + i) = *(node -> keys_info + i + 1);
    }

    *(node -> keys_info + num_keys - 1) = NULL;

    node->num_keys -= 1;

    if (free_key_info == 1){
        free(removed_key_info -> data);
        free(removed_key_info);
    }
    
    return node->num_keys;
}

int need_split(Btree_Node* node, uint16_t branching){
    // parent node
    if (node == NULL){
        return 0;
    }
    if (node -> num_keys > branching - 1){
        return 1;
    }
    else{
        return 0;
    }
}


void add_children(Btree_Node * left_child, Btree_Node * right_child, Btree_Node * original_child, Btree_Node * parent){
    // since the position of the original_child
    Btree_Node ** children_address_ptr = parent->children;
    int position = 0;
    for (;  *(children_address_ptr + position) != NULL; position++){
        if (*(children_address_ptr + position) == original_child){
            break;
        }
    }
  
    // move all the children after it one position backward
    for (int i = parent->num_keys; i >= position; i--){
        *(parent -> children + i + 1) = *(parent -> children + i);
    }

    *(children_address_ptr + position) = left_child;
    *(children_address_ptr + position + 1) = right_child;
}


void splitNode(Btree_Node* node, uint16_t branching, void *helper){
    if (need_split(node, branching) == 0){
        return;
    }

    uint16_t * num_nodes = (uint16_t *)(helper + 3); 
    Btree_Node * new_left = initialize_Btree_node(branching, NULL);
    Btree_Node * new_right = initialize_Btree_node(branching, NULL);

    int num_keys = node -> num_keys;
    int middle_key_index = 0;
    if (num_keys % 2 == 0){
        // 0 1 2 3. num is 4
        // middle_key_index is 1, 4/2 -1
        middle_key_index = num_keys / 2 - 1;
        if (node->num_children != 0){
            new_left->num_children = node->num_children /2;
            new_right->num_children = node->num_children /2 + 1;
        }
        
        

    }else{
        // 0 1 2 num is 3
        // middle_key_index is 1, 
        middle_key_index = num_keys / 2;
        if (node->num_children != 0){
            new_left->num_children = node->num_children /2;
            new_right->num_children = node->num_children /2;
        }
    }

    // add the keys (At the same time add keys_info)
    // split children
    for (int i = 0; i < num_keys; i++){
        uint32_t key = *(node -> keys + i);
        struct info * key_info_ptr = *((node -> keys_info) + i);
        // keys                 0     1(m)   2     3
        // children         c0    c1    c2     c3    c4
        

        // keys                 0      1(m)   2
        // children         c0      c1    c2     c3

        if (i < middle_key_index){
            add_key_in_one_node(new_left, key, key_info_ptr);
            *(new_left->children + i) = *(node -> children + i);
            if (*(new_left -> children + i) != NULL){
                (*(new_left->children + i)) -> parent = new_left;
            }
            
        }

        else if (i == middle_key_index){
            *(new_left->children + i) = *(node -> children + i);
            if (*(new_left -> children + i) != NULL){
                (*(new_left->children + i)) -> parent = new_left;
            }
        }

        else{
            add_key_in_one_node(new_right, key, key_info_ptr);
            *(new_right->children + i - middle_key_index - 1) = *(node -> children + i);
            if(*(new_right->children + i - middle_key_index - 1) != NULL){
                (*(new_right->children + i - middle_key_index - 1)) -> parent = new_right;
            }
            
        }
    }
    *(new_right->children + num_keys - middle_key_index - 1) = *(node -> children + num_keys);
    if(*(new_right->children + num_keys - middle_key_index - 1) != NULL){
        (*(new_right->children + num_keys - middle_key_index - 1)) -> parent = new_right;
    }
   


    // add the middle key into its parent
    Btree_Node * parent = node -> parent;
    if (parent != NULL){
        (*num_nodes)++;

        add_children(new_left, new_right, node, parent);
     
        add_key_in_one_node(parent, *(node -> keys + middle_key_index), *(node -> keys_info + middle_key_index));
        new_left -> parent = parent;
        new_right -> parent = parent;
        parent->num_children += 1;
    }else{
        (*num_nodes) += 2;
        // create a new node as root, this middle one
        Btree_Node * new_root = initialize_Btree_node(branching, NULL);
        add_key_in_one_node(new_root, *(node -> keys + middle_key_index), *(node -> keys_info + middle_key_index));

        *(new_root -> children + 0) = new_left;
        *(new_root -> children + 1) = new_right;

        new_left -> parent = new_root;
        new_right -> parent = new_root;

        // put the new root address into heapstart

        Btree_Node ** root_ptr = (Btree_Node **) (helper + 5);
        *root_ptr = new_root;
        new_root ->num_children = 2;
    }
    

    // free the original node
    // children pointers are copied into new node
    // SO just need to free

    // At this place, we can not free the total node originally
    // We only need to free keys since keys are copied to new node, 
    // but the pointer in keys_info and child can't.
    // just free the space, not the address in keys_info and child
    // free_one_node(&node);

    free(node -> keys);
    free(node -> keys_info);
    free(node -> children);
    free(node);

    splitNode(parent, branching, helper);

}


Btree_Node* recursive_find(uint32_t target_key, struct info * found, Btree_Node * root){
    Btree_Node * cur = root;

    if (cur == NULL){
        return NULL;
    }
    

    for (int i = 0; i < cur -> num_keys; i++){
        
        if (*(cur -> keys + i) == target_key){
            *found = **(cur -> keys_info + i);
            return cur;
        }
        
        if (target_key < *(cur -> keys + i)){
            return recursive_find(target_key, found, *(cur -> children + i));
            break;
        }

        if (i == cur -> num_keys - 1 && target_key > *(cur -> keys + i)){
            return recursive_find(target_key, found, *(cur -> children + i + 1));
            break;
        }

    }

    return NULL;

}




void find_maximum_node(Btree_Node* root, Btree_Node** res, uint32_t* maximum_key){
    Btree_Node * cur = root;
    if (cur == NULL){
        return;
    }

    for (int i = 0; i < cur -> num_keys; i++){
        if (*(cur->keys + i) > *maximum_key){
            *maximum_key = *(cur->keys + i);
            *res = cur;
        }
    }

    for (int i = 0; i < cur -> num_keys + 1; i++){
        Btree_Node * child = *(cur -> children + i);
        find_maximum_node(child, res, maximum_key);
    }
}


void swap_key(uint32_t key1, Btree_Node* node1, uint32_t key2, Btree_Node* node2){
    uint16_t position1 = 0;
    uint16_t position2 = 0;
    
    find_position_of_key(node1, key1, &position1);
    find_position_of_key(node2, key2, &position2);

    *(node1->keys + position1) = key2;
    *(node2->keys + position2) = key1;

    struct info * tmp = *(node1->keys_info + position1);
    *(node1->keys_info + position1) = *(node2->keys_info + position2);
    *(node2->keys_info + position2) = tmp;
}



void replace_key(Btree_Node* node_replaced, uint32_t key_replaced, Btree_Node* node, u_int32_t key){
    uint16_t position_r;
    uint16_t position;
    find_position_of_key(node_replaced, key_replaced, &position_r);
    find_position_of_key(node, key, &position);

    *(node_replaced->keys + position_r) = *(node->keys + position);
    *(node_replaced->keys_info + position_r) = *(node->keys_info + position);

}

void merge_two_nodes(Btree_Node* target, Btree_Node* node_be_merged, void *helper){

    for (uint16_t i = 0; i < node_be_merged -> num_keys; i++){
        uint32_t key = *(node_be_merged->keys + i);
        struct info* key_info = *(node_be_merged->keys_info + i);
        add_key_in_one_node(target, key, key_info);
        
    }

    

    if (target->num_children != 0){
        // not a leaf, merge children and change their parent

        for (int i = target->num_children; i < target->num_children + node_be_merged->num_children; i++){
            *(target->children + i) = *(node_be_merged->children + i - (target->num_children));
            (*(node_be_merged->children + i - (target->num_children))) -> parent = target;
        }

        target->num_children += node_be_merged->num_children;
    }
  
    // the we delete the node_be_merged
    // 1. delete its address in parent
    // 2. free the node, not free the key_info and data
    // 3. num_node --

    delete_one_node(&node_be_merged, helper);

}

// left most is 0, rightmost is 1
void move_child(Btree_Node * dest_node, Btree_Node *child, Btree_Node * original_node, int leftmost_or_rightmost){
    uint16_t position;
    find_position_of_child(original_node, child, &position);
    if (leftmost_or_rightmost == 1){
        // move leftmost child to rightmost
        // original node's children: leftmost -> NULL, move all the children one position ahead, num_children--
        
        // update the children in original_node
        for (;position < original_node->num_children - 1; position++){
            *(original_node->children + position) = *(original_node->children + position + 1);
        }
        original_node->num_children -= 1;
    }else{
        original_node->num_children -= 1;
    }

    // update the new parent's child
    if (leftmost_or_rightmost == 1){
        // put the child into rightmost
        *(dest_node->children + (dest_node->num_keys)) = child;
    }else{
        // put the child int leftmost
        // need to move all the child right first
        for(int i = dest_node->num_keys - 1; i >= 0 ; i--){
            *(dest_node-> children + i + 1) = *(dest_node->children + i);
        }
        *(dest_node->children) = child;
    }
    
    child->parent = dest_node;

    dest_node->num_children += 1;
    
    
}


void balance_internal(Btree_Node *internal_node, int min_key_num, Btree_Node* last_child, void* helper){
    if (internal_node->num_keys >= min_key_num){
        return; 
    }
    if (internal_node->parent == NULL){
        if (internal_node->num_keys == 0){
            
            // simply removed the node and update the new root which is the merged child
            // remember to update the helper
            Btree_Node* original_root = *((Btree_Node **) (helper + 5));
            
            *((Btree_Node **) (helper + 5)) = last_child;
     
            last_child->parent = NULL;

            free_one_node(&original_root);
            
            uint16_t * num_nodes = (uint16_t *)(helper + 3); 
            (*num_nodes) -= 1;
            return;
        }else{
            return;
        }
    }

    Btree_Node* parent = internal_node->parent;
    Btree_Node* left_sibling = NULL;
    uint32_t key_left = 0;
    struct info* key_left_info = NULL;

    Btree_Node* right_sibling = NULL;
    uint32_t key_right = 0;
    struct info* key_right_info = NULL;


    // 1. find position of current node, if it is leftmost(0), we just consider right sibling
    //    if there are no left sibling has more than min_key_num, consider right sibling
    uint16_t index = 0;
    find_position_of_child(internal_node->parent, internal_node, &index);
    // leftmost, 
    if (index == 0){
        right_sibling = *(parent->children + 1 + index);
        //   correct at this stage 
        key_right = *(parent->keys + index);
        uint32_t key_right_child = *(right_sibling->keys);
        key_right_info = *(parent->keys_info + index);
        struct info* key_right_child_info = *(right_sibling->keys_info);

        // find the smallest child of right_sibling
        Btree_Node* child_smallest = *(right_sibling->children);

        if (right_sibling->num_keys > min_key_num){
            // key_right is the key in parent split it
            add_key_in_one_node(internal_node, key_right, key_right_info);
            delete_key_in_one_node(parent, key_right, 0);
            add_key_in_one_node(parent, key_right_child, key_right_child_info);
            delete_key_in_one_node(right_sibling, key_right_child, 0);
            
            move_child(internal_node, child_smallest, right_sibling, 1);
            return;
        }else{
            // can  only merge with right sibling
            
            add_key_in_one_node(internal_node, key_right, key_right_info);
      
            delete_key_in_one_node(parent, key_right, 0);
          
            
            merge_two_nodes(internal_node, right_sibling, helper);

            balance_internal(parent, min_key_num, internal_node, helper);
        }
        

    }
    // rightmost
    else if (index == internal_node->parent->num_keys){
        left_sibling = *(parent->children + index - 1);
        key_left = *(parent->keys + index - 1);
        // last key in left_sibling
        uint32_t key_left_child = *(left_sibling->keys + left_sibling->num_keys - 1);
        key_left_info = *(parent->keys_info + index - 1);
        struct info* key_left_child_info = *(left_sibling->keys_info + left_sibling->num_keys - 1);

        // find the largest child of left_sibling
        Btree_Node* child_largest = *(left_sibling->children + left_sibling->num_keys);

        if (left_sibling-> num_keys > min_key_num){
            add_key_in_one_node(internal_node, key_left, key_left_info);
            delete_key_in_one_node(parent, key_left, 0);
            add_key_in_one_node(parent, key_left_child, key_left_child_info);
            delete_key_in_one_node(left_sibling, key_left_child, 0);

            move_child(internal_node, child_largest, left_sibling, 1);
            return;
        }

        else{
            // can only merge with left sibling
            add_key_in_one_node(internal_node, key_left, key_left_info);
            // delete it from parent node, not free the key info
            delete_key_in_one_node(parent, key_left, 0);
            // move all keys in immediate sibling to target node,
           
            merge_two_nodes(internal_node, left_sibling, helper);
         
            // After this step, there will be internal nodes
            balance_internal(parent, min_key_num, internal_node, helper);
        }
        


    }
    // middle
    else{
        left_sibling = *(parent->children + index - 1);
        key_left = *(parent->keys + index - 1);
        // last key in left_sibling
        uint32_t key_left_child = *(left_sibling->keys + left_sibling->num_keys - 1);
        key_left_info = *(parent->keys_info + index - 1);
        struct info* key_left_child_info = *(left_sibling->keys_info + left_sibling->num_keys - 1);

        // find the largest child of left_sibling
        Btree_Node* child_largest = *(left_sibling->children + left_sibling->num_keys);

        if (left_sibling-> num_keys > min_key_num){
            add_key_in_one_node(internal_node, key_left, key_left_info);
            delete_key_in_one_node(parent, key_left, 0);

            add_key_in_one_node(parent, key_left_child, key_left_child_info);
            delete_key_in_one_node(left_sibling, key_left_child, 0);

            move_child(internal_node, child_largest, left_sibling, 1);
           
            return;
        }

        right_sibling = *(parent->children + 1 + index);
        //   correct at this stage 
        key_right = *(parent->keys + index);
        uint32_t key_right_child = *(right_sibling->keys);
        key_right_info = *(parent->keys_info + index);
        struct info* key_right_child_info = *(right_sibling->keys_info);

        // find the smallest child of right_sibling
        Btree_Node* child_smallest = *(right_sibling->children);
        if (right_sibling->num_keys > min_key_num){
            // key_right is the key in parent split it
            add_key_in_one_node(internal_node, key_right, key_right_info);
            delete_key_in_one_node(parent, key_right, 0);
            add_key_in_one_node(parent, key_right_child, key_right_child_info);
            delete_key_in_one_node(right_sibling, key_right_child, 0);

            move_child(internal_node, child_smallest, right_sibling, 1);
            return;
        }else{

            // both exists, merge with left sibling first;
            add_key_in_one_node(internal_node, key_left, key_left_info);
            // delete it from parent node, not free the key info
            delete_key_in_one_node(parent, key_left, 0);
            // move all keys in immediate sibling to target node,
           
            merge_two_nodes(internal_node, left_sibling, helper);
         
            // After this step, there will be internal nodes
            balance_internal(parent, min_key_num, internal_node, helper);
        }

    }

}




void preorder(Btree_Node * root, struct node *list, int num_nodes){
    Btree_Node* cur = root;
    if (cur == NULL){
        return;
    }
    
    for (int i = 0; i < num_nodes ; i++){
        struct node *n = list + i;
        
        if (n -> num_keys == 0){
 
            n -> num_keys = cur -> num_keys;
            n -> keys = (uint32_t *) malloc(cur->num_keys * sizeof(uint32_t));

            memcpy(n->keys, cur->keys, cur->num_keys * sizeof(uint32_t));
            break;
        }
    }
 
    for (uint16_t i = 0; i < cur -> num_keys + 1; i++){
        Btree_Node* child = *(cur->children + i);
        preorder(child, list, num_nodes);
    }


}

