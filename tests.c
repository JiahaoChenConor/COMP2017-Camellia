#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include "cmocka.h"
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>


#include "btreestore.h"
uint32_t encrypt_key[4];
uint64_t nonce = 0x1234123412341234;


static int setup(void **state){
    *state = init_store(4, 4);
    encrypt_key[0] = 0x12345678;
    encrypt_key[1] = 0x23456789;
    encrypt_key[2] = 0x3456789A;
    encrypt_key[3] = 0x456789AB;
    return 0;
}

static int teardown(void **state){
    close_store(*state);
    return 0;
}

static void test_encrypt_tea(void ** state){
    uint32_t plain[2];
    uint32_t cipher[2];
    memcpy(plain, "abcdefg", sizeof(uint32_t) * 2);
    encrypt_tea(plain, cipher, encrypt_key);
    assert_int_equal(cipher[0], 0xbd620d19);
    assert_int_equal(cipher[1], 0xf54f8194);
}

static void test_decrypt_tea(void ** state){
    uint32_t plain[2];
    uint32_t cipher[2];
    cipher[0] = -1117647591;
    cipher[1] = -179338860;
    decrypt_tea(cipher, plain, encrypt_key);
    assert_int_equal(cipher[0], 0x64636261);
    assert_int_equal(cipher[1], 0x676665);
}

static void test_encrypt_tea_ctr(void ** state){
    void * plain = malloc(16);
    void * cipher = malloc(16);
    memcpy(plain, "abcdefghijklmno", 16);
    encrypt_tea_ctr(plain, encrypt_key, nonce, cipher, 2);
    uint32_t *p = (uint32_t *) cipher;
    assert_int_equal(*(p), 0xb4c59a2e);
    assert_int_equal(*(p + 1), 0x81f619a8);
    assert_int_equal(*(p + 2), 0x422c54a1);
    assert_int_equal(*(p + 3), 0x3c2383be);
    free(plain);
    free(cipher);
}

static void test_decrypt_tea_ctr(void ** state){
    void * plain = malloc(16);
    void * cipher = malloc(16);
    uint32_t * p = (uint32_t *) cipher;
    uint32_t * res = (uint32_t *) plain;
    *p = 0xb4c59a2e;
    *(p + 1) = 0x81f619a8;
    *(p + 2) = 0x422c54a1;
    *(p + 3) = 0x3c2383be;

    encrypt_tea_ctr(cipher, encrypt_key, nonce, plain, 2);
    assert_int_equal(*(res), 0x64636261);
    assert_int_equal(*(res + 1), 0x68676665);
    assert_int_equal(*(res + 2), 0x6c6b6a69);
    assert_int_equal(*(res + 3), 0x6f6e6d);
    free(plain);
    free(cipher);

}

// Test 1: Test basic insert
static void insert_basic(void **state){
    int inserted_keys[11] = {2, 3, 1, 8, 80, 5, 6, 4, 20, 21, 22};
    for (int i = 0; i < 11; i++){
        btree_insert(inserted_keys[i], "a", 2, encrypt_key, nonce, *state);
    }
    
}

// Test 2: Test insert nothing
static void insert_nothing(void **state){
}


// Test 3: Test complex insert
static void insert_complex(void **state){
    for (int i = 0; i < 4500; i++){
        btree_insert(i, "a", 2, encrypt_key, nonce, *state);
    }
}

// Test 4: Retrieve basic (successfully)
static void retrieve_basic(void **state){
    insert_basic(state);
    struct info found;
    int res = btree_retrieve(3, &found, *state);
    assert_int_equal(res, 0);
}

// Test 5: Retrieve (not found)
static void retrieve_not_found(void **state){
    insert_basic(state);
    struct info found;
    int res = btree_retrieve(100, &found, *state);
    assert_int_equal(res, 1);
}

// Test 6: Delete found
static void delete_found(void **state){
    for (int i = 513434; i < 513701; i++){
        btree_insert(i, "a", 2, encrypt_key, nonce, *state);
    }
    int ret = btree_delete(513434, *state);
    assert_int_equal(ret, 0);
    btree_insert(513701, "a", 2, encrypt_key, nonce, *state);
    ret = btree_delete(513435, *state);
    assert_int_equal(ret, 0);
}

// Test 7: Delete not found
static void delete_not_found(void **state){
    for (int i = 4; i < 20; i++){
        btree_insert(i, "a", 2, encrypt_key, nonce, *state);
    }
    int ret = btree_delete(21, *state);
    assert_int_equal(ret, 1);
}


void export_info(void * helper, char* test_num){
    freopen("tests_out/temp.out", "w", stdout);

    struct node *list = NULL;
    int num_of_nodes = btree_export(helper, &list);
    printf("number of nodes: %d\n", num_of_nodes);
    if (num_of_nodes != 0){
        for (int i = 0; i < num_of_nodes; i++){
            printf("keys in this node: ");
            for (int j = 0; j < (list + i) -> num_keys; j++){
                printf("%d ", *((list + i) -> keys + j));
            }
            free((list + i) -> keys);
            printf("\n");
        }
        free(list);
    }
    
    freopen("/dev/tty", "w", stdout);

    // compare the result
    char filename[18] = "tests_out/out.";
    strcat(filename, test_num);

    char string_a[1024];
    char string_b[1024];
    FILE* F_a = fopen(filename, "r");
    FILE* F_b = fopen(filename, "r");

    while(!feof(F_a) && !feof(F_b)){
        fgets(string_a, 1024, F_a);
        fgets(string_b, 1024, F_b);
        assert_string_equal(string_a, string_b);
    }
}
// Test 8: Export
static void basic_export(void ** state){
    for (int i = 4; i < 20; i++){
        btree_insert(i, "a", 2, encrypt_key, nonce, *state);
    }
    export_info(*state, "8");

}

static void insert_delete_large_num_nodes(void ** state){
    for (int i = 513434; i < 513701; i++){
        btree_insert(i, "a", 2, encrypt_key, nonce, *state);
    }
    btree_delete(513434, *state);
    btree_insert(513701, "a", 2, encrypt_key, nonce, *state);
    btree_delete(513435, *state);
    btree_insert(513702, "a", 2, encrypt_key, nonce, *state);

    export_info(*state, "9");
}

static void tree_decrypt_success(void ** state){
    btree_insert(1, "a", 2, encrypt_key, nonce, *state);
    btree_insert(2, "b", 2, encrypt_key, nonce, *state);
    btree_insert(3, "c", 2, encrypt_key, nonce, *state);
    btree_insert(4, "d", 2, encrypt_key, nonce, *state);
    btree_insert(5, "e", 2, encrypt_key, nonce, *state);

    void* message = malloc(2);
    int ret = btree_decrypt(4, message, *state);
    assert_int_equal(ret, 0);
    char * m = (char *)message;
    assert_string_equal(m, "d");
    free(message);
}

static void tree_decrypt_fail(void ** state){
    btree_insert(1, "a", 2, encrypt_key, nonce, *state);
    btree_insert(2, "b", 2, encrypt_key, nonce, *state);
    btree_insert(3, "c", 2, encrypt_key, nonce, *state);
    btree_insert(4, "d", 2, encrypt_key, nonce, *state);
    btree_insert(5, "e", 2, encrypt_key, nonce, *state);

    void* message = malloc(2);
    int ret = btree_decrypt(10, message, *state);
    assert_int_equal(ret, 1);
    free(message);
}




void * insert_basic_thread(void * argv){
    for (int i = 0; i < 1000; i++){
        btree_insert(i, "a", 2, encrypt_key, nonce, argv);
    }
    return NULL;
}


static void multithreaded_insert(void **state){
    pthread_t thread_insert_ID[10];

    for (int i = 0; i < 10; i++){
         pthread_create(thread_insert_ID + i, NULL, &insert_basic_thread, *state);
    }
    
    for (int i = 0; i < 10; i++){
        pthread_join(thread_insert_ID[i], NULL);
    }
    
}

void * insert_large_encrypt_data(void * argv){
    char data[50000];
    for (int i = 0; i < 10; i++){
        btree_insert(i, data, 2, encrypt_key, nonce, argv);
    }
    return NULL;
}

static void multithreaded_insert_large_encrypt_data(void ** state){
    pthread_t thread_insert_ID[10];

    for (int i = 0; i < 10; i++){
         pthread_create(thread_insert_ID + i, NULL, &insert_large_encrypt_data, *state);
    }
    
    for (int i = 0; i < 10; i++){
        pthread_join(thread_insert_ID[i], NULL);
    }
}


void * retrieve_basic_thread(void * argv){
    struct info found;
    int res = btree_retrieve(10, &found, argv);
    assert_int_equal(res, 0);
    return NULL;
}


static void multithreaded_retrieve(void **state){
    pthread_t thread_insert_ID[10];
    

    for (int i = 0; i < 10; i++){
         pthread_create(thread_insert_ID + i, NULL, &insert_basic_thread, *state);
    }
    
    for (int i = 0; i < 10; i++){
        pthread_join(thread_insert_ID[i], NULL);
    }

    for (int i = 0; i < 10; i++){
         pthread_create(thread_insert_ID + i, NULL, &retrieve_basic_thread, *state);
    }

    for (int i = 0; i < 10; i++){
        pthread_join(thread_insert_ID[i], NULL);
    }

}

void * delete_basic_thread(void * argv){
    for (int i = 0; i < 1000; i++){
        btree_delete(i, argv);
    }
    return NULL;
}


static void multithreaded_insert_delete(void **state){
    pthread_t thread_insert_ID[10];
    pthread_t thread_delete_ID[10];

    for (int i = 0; i < 10; i++){
         pthread_create(thread_insert_ID + i, NULL, &insert_basic_thread, *state);
    }

    for (int i = 0; i < 10; i++){
         pthread_create(thread_delete_ID + i, NULL, &delete_basic_thread, *state);
    }
    
    for (int i = 0; i < 10; i++){
        pthread_join(thread_insert_ID[i], NULL);
    }


    for (int i = 0; i < 10; i++){
        pthread_join(thread_delete_ID[i], NULL);
    }

}

static void multithreaded_combination_huge(void **state){
    pthread_t thread_insert_ID[100];
    pthread_t thread_delete_ID[100];

    for (int i = 0; i < 100; i++){
         pthread_create(thread_insert_ID + i, NULL, &insert_basic_thread, *state);
    }

    for (int i = 0; i < 100; i++){
         pthread_create(thread_delete_ID + i, NULL, &delete_basic_thread, *state);
    }
    
    for (int i = 0; i < 100; i++){
        pthread_join(thread_insert_ID[i], NULL);
    }


    for (int i = 0; i < 100; i++){
        pthread_join(thread_delete_ID[i], NULL);
    }
}



int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_encrypt_tea, setup, teardown),
        cmocka_unit_test_setup_teardown(test_decrypt_tea, setup, teardown),
        cmocka_unit_test_setup_teardown(test_encrypt_tea_ctr, setup, teardown),
        cmocka_unit_test_setup_teardown(test_decrypt_tea_ctr, setup, teardown),
        cmocka_unit_test_setup_teardown(insert_basic, setup, teardown),
         cmocka_unit_test_setup_teardown(insert_nothing, setup, teardown),
          cmocka_unit_test_setup_teardown(insert_complex, setup, teardown),
          cmocka_unit_test_setup_teardown(retrieve_basic, setup, teardown),
          cmocka_unit_test_setup_teardown(retrieve_not_found, setup, teardown),
          cmocka_unit_test_setup_teardown(delete_found, setup, teardown),
          cmocka_unit_test_setup_teardown(delete_not_found, setup, teardown),
          cmocka_unit_test_setup_teardown(basic_export, setup, teardown),
          cmocka_unit_test_setup_teardown(insert_delete_large_num_nodes, setup, teardown),
          cmocka_unit_test_setup_teardown(tree_decrypt_success, setup, teardown),
          cmocka_unit_test_setup_teardown(tree_decrypt_fail, setup, teardown),
          cmocka_unit_test_setup_teardown(multithreaded_insert, setup, teardown),
          cmocka_unit_test_setup_teardown(multithreaded_insert_large_encrypt_data, setup, teardown),
          cmocka_unit_test_setup_teardown(multithreaded_retrieve, setup, teardown),
          cmocka_unit_test_setup_teardown(multithreaded_insert_delete, setup, teardown),
          cmocka_unit_test_setup_teardown(multithreaded_combination_huge, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
