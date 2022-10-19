#include "../include/aes-128_enc.h"

/**************************************************************************************************/
/* 										 								                          */
/* 					              Question 1 dans aes-128_enc.c                                   */
/* 										 								                          */
/**************************************************************************************************/

/**************************************************************************************************/
/* 										 								                          */
/* 					              Question 2 dans aes-128_enc.c                                   */
/* 										 								                          */
/**************************************************************************************************/

/**************************************************************************************************/
/* 										 								                          */
/* 					                    Question 3                                                */
/* 				k1 and k2 different to not xor the same values wich is equal to 0                 */
/* 										 								                          */
/* 										 								                          */
/* 										 								                          */
/**************************************************************************************************/
void keyedFunction(uint8_t block[AES_BLOCK_SIZE], uint8_t *key)
{
    uint8_t key1[AES_128_KEY_SIZE], key2[AES_128_KEY_SIZE];
    uint8_t block1[AES_BLOCK_SIZE], block2[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        key1[i] = key[i];
        block1[i] = block[i];
        block2[i] = block[i];
    }
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        key1[i + AES_BLOCK_SIZE] = key[i + AES_BLOCK_SIZE];
    }
    aes128_enc(block1, key1, 3, 1);
    aes128_enc(block2, key2, 3, 1);
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        block[i] = block1[i] ^ block2[i];
    }
}

int main()
{

    uint8_t key[32];
    uint8_t block[16];

    for (int i = 0; i < 32; i++)
    {
        srand(clock());
        key[i] = rand() % 256;
    }
    for (int i = 0; i < 16; i++)
    {
        srand(clock());
        block[i] = rand() % 256;
    }
    printf("========================== Block to sipher ========================== \n");

    for (int i = 0; i < 16; i++)
    {
        printf("[0x%x]", block[i]);
    }
    puts(" ");
    keyedFunction(block, key);
    printf("========================== Block siphered ========================== \n");

    for (int i = 0; i < 16; i++)
    {
        printf("[0x%x]", block[i]);
    }
    puts(" ");
}