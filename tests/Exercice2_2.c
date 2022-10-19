#include "../include/aes-128_enc.h"
/*
 *           changing the representation of F2^8   (check finction xtime1 and aes128_enc1 they are the same as other function but in diffrent represention)
 */
/*
 *           changing also the S-box   (check finction xtime1 and aes128_enc1 they are the same as other function but in diffrent represention)
 */
int main()
{

    /**************************************************************************************************/
    /* 										 					                                      */
    /* 										1)Generate a key     			                          */
    /* 										2)Initialise our block 	    			                  */
    /* 										3)Initialise our gueesed key 			                  */
    /* 										 					                                      */
    /**************************************************************************************************/
    uint8_t key_c[16], key_th[16];
    uint8_t key[16];
    printf("Key to find:\n");
    for (int i = 0; i < 16; i++)
    {
        srand(clock());
        key[i] = rand() % 256;
        printf("[0x%x]", key[i]);
    }
    puts(" ");
    printf("==========================================");
    puts(" ");
    printf("Checking ...\n");
    uint8_t **block;

    uint8_t **keyGuess = intialisationMatrix(16, 256, 1, 0);

    /**************************************************************************************************/
    /* 							4 round encryption with the key key_th[16]                        	  */
    /* 									 First we set our random Λ-set                            	  */
    /*				                        That we sipher (4 rounds)                              	  */
    /**************************************************************************************************/
    block = intialisationMatrix(256, 16, rand() % 256, 1);
    for (int i = 0; i < 256; i++)
        aes128_enc1(block[i], key, 4, 0);
    /**************************************************************************************************/
    /* 										 								                          */
    /* 					Now we search for a key to the corresponding output block                     */
    /* 										 								                          */
    /**************************************************************************************************/
    porentielkEY1(block, keyGuess, key_th);

    while (falsepositive(keyGuess)) // If there is more then 2 candidates for a block we generate an other Λ-set to eleminate false candidates
    {
        /**************************************************************************************************/
        /*				Each Λ-set will help us eleminate candidates for the blocks of the key         	  */
        /*	the nombre of candidate will dicrease until their will be only one and only candidate for 	  */
        /*									  each block of the key						              	  */
        /**************************************************************************************************/
        block = intialisationMatrix(256, 16, rand() % 256, 1);
        for (int i = 0; i < 256; i++)
            aes128_enc1(block[i], key, 4, 0);
        /**************************************************************************************************/
        /* 										 								                          */
        /* 			Now we eleminate false candidates by simply testing their credibility                 */
        /* 										 								                          */
        /**************************************************************************************************/
        porentielkEY1(block, keyGuess, key_th);

        /**************************************************************************************************/
        /* 								If no self positive we found the key	                          */
        /* 									If it's not the case we retry                                 */
        /**************************************************************************************************/
    }

    prev_aes128_round_key1(key_th, key_c, 4);
    prev_aes128_round_key1(key_c, key_th, 3);
    prev_aes128_round_key1(key_th, key_c, 2);
    prev_aes128_round_key1(key_c, key_th, 1);

    printf("Key found:\n");
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

    return 0;
}
