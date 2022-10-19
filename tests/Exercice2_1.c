#include "../include/aes-128_enc.h"
/*
 *           Test the detection of more then a 50 key: this test generate 50 keys that we use to sipher Λ-set
 *           then we try to find each key.
 */

int main()
{
    printf("Checking ...\n");
    int success = 0, failed = 0;
    for (int keysTry = 0; keysTry < 50; keysTry++)
    {
        /**************************************************************************************************/
        /* 										 					                                      */
        /* 										1)Generate a key     			                          */
        /* 										2)Initialize our block Λ-set       			                  */
        /* 										3)Initialize our gueesed key 			                  */
        /* 										 					                                      */
        /**************************************************************************************************/
        uint8_t key_c[16], key_th[16];
        uint8_t key[16];

        for (int i = 0; i < 16; i++)
        {
            srand(clock());
            key[i] = rand() % 256;
        }
        uint8_t **block;

        uint8_t **keyGuess = intialisationMatrix(16, 256, 1, 0);

        /**************************************************************************************************/
        /* 							4 round encryption with the key key_th[16]                        	  */
        /* 									 First we set our random Λ-set                            	  */
        /*				                        That we sipher (4 rounds)                              	  */
        /**************************************************************************************************/
        block = intialisationMatrix(256, 16, rand() % 256, 1);
        for (int i = 0; i < 256; i++)
            aes128_enc(block[i], key, 4, 0);
        /**************************************************************************************************/
        /* 										 								                          */
        /* 					Now we search for a key to the corresponding output block                     */
        /* 										 								                          */
        /**************************************************************************************************/
        porentielkEY(block, keyGuess, key_th);

        while (falsepositive(keyGuess)) // If there is more then 2 candidates for a block we generate an other Λ-set to eleminate false candidates
        {
            /**************************************************************************************************/
            /*				Each Λ-set will help us eleminate candidates for the blocks of the key         	  */
            /*	the nombre of candidate will dicrease until their will be only one and only candidate for 	  */
            /*									  each block of the key						              	  */
            /**************************************************************************************************/
            block = intialisationMatrix(256, 16, rand() % 256, 1);
            for (int i = 0; i < 256; i++)
                aes128_enc(block[i], key, 4, 0);
            /**************************************************************************************************/
            /* 										 								                          */
            /* 			Now we eleminate false candidates by simply testing their credibility                 */
            /* 										 								                          */
            /**************************************************************************************************/
            porentielkEY(block, keyGuess, key_th);

            /**************************************************************************************************/
            /* 								If no self positive we found the key	                          */
            /* 									If it's not the case we retry                                 */
            /**************************************************************************************************/
        }

        prev_aes128_round_key(key_th, key_c, 4);
        prev_aes128_round_key(key_c, key_th, 3);
        prev_aes128_round_key(key_th, key_c, 2);
        prev_aes128_round_key(key_c, key_th, 1);

        printf("Key found:");
        for (int j = 0; j < 16; j++)
        {
            printf("[0x%x]", key_th[j]);
        }

        puts(" ");

        int similar = 0;
        for (int j = 0; j < 16; j++)
        {
            if (key[j] == key_th[j])
                similar++;
        }
        puts(" ");

        if (similar == 16)
            success++;
        // printf("================== ATTACK SUCCESS ==================\n\n\n\n");
        else
            failed++;
        // printf("================== ATTACK FAILED ==================\n\n\n\n");
        // printf("===================Q2 a different cipher TESTED OK===============\n");
        // uint8_t aBlock[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    }
    printf("-----%d keys found     \n", success);
    printf("-----%d keys not found \n", failed);

    return 0;
}