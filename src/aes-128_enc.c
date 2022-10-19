/*
 * AES-128 Encryption
 * Byte-Oriented
 * On-the-fly key schedule
 * Constant-time XTIME
 */

#include "../include/aes-128_enc.h"

/*
 * Constant-time ``broadcast-based'' multiplication by $a$ in $F_2[X]/X^8 + X^4 + X^3 + X + 1$
 */

// all functions that are duplicated (function1) they have the same application but in a new representation
uint8_t xtime(uint8_t p)
{
	uint8_t m = p >> 7;

	m ^= 1;
	m -= 1;
	m &= 0x1B;

	return ((p << 1) ^ m);
}

uint8_t xtime1(uint8_t p)
{
	uint8_t m = p >> 7;
	if (m & 1)
	{
		m = 0x7B; // representation in hexadecimal of X6+X5+X4+X3+X+1
	}
	return ((p << 1) ^ m);
}

/*
 * The round constants
 */
static const uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

void aes_round(uint8_t block[AES_BLOCK_SIZE], uint8_t round_key[AES_BLOCK_SIZE], int lastround)
{
	int i;
	uint8_t tmp;

	/*
	 * SubBytes + ShiftRow
	 */
	/* Row 0 */
	block[0] = S[block[0]];
	block[4] = S[block[4]];
	block[8] = S[block[8]];
	block[12] = S[block[12]];
	/* Row 1 */
	tmp = block[1];
	block[1] = S[block[5]];
	block[5] = S[block[9]];
	block[9] = S[block[13]];
	block[13] = S[tmp];
	/* Row 2 */
	tmp = block[2];
	block[2] = S[block[10]];
	block[10] = S[tmp];
	tmp = block[6];
	block[6] = S[block[14]];
	block[14] = S[tmp];
	/* Row 3 */
	tmp = block[15];
	block[15] = S[block[11]];
	block[11] = S[block[7]];
	block[7] = S[block[3]];
	block[3] = S[tmp];

	/*
	 * MixColumns
	 */
	for (i = lastround; i < 16; i += 4) /* lastround = 16 if it is the last round, 0 otherwise */
	{
		uint8_t *column = block + i;
		uint8_t tmp2 = column[0];
		tmp = column[0] ^ column[1] ^ column[2] ^ column[3];

		column[0] ^= tmp ^ xtime(column[0] ^ column[1]);
		column[1] ^= tmp ^ xtime(column[1] ^ column[2]);
		column[2] ^= tmp ^ xtime(column[2] ^ column[3]);
		column[3] ^= tmp ^ xtime(column[3] ^ tmp2);
	}

	/*
	 * AddRoundKey
	 */
	for (i = 0; i < 16; i++)
	{
		block[i] ^= round_key[i];
	}
}

void aes_round1(uint8_t block[AES_BLOCK_SIZE], uint8_t round_key[AES_BLOCK_SIZE], int lastround)
{
	int i;
	uint8_t tmp;

	/*
	 * SubBytes + ShiftRow
	 */
	/* Row 0 */
	block[0] = S1[block[0]];
	block[4] = S1[block[4]];
	block[8] = S1[block[8]];
	block[12] = S1[block[12]];
	/* Row 1 */
	tmp = block[1];
	block[1] = S1[block[5]];
	block[5] = S1[block[9]];
	block[9] = S1[block[13]];
	block[13] = S1[tmp];
	/* Row 2 */
	tmp = block[2];
	block[2] = S1[block[10]];
	block[10] = S1[tmp];
	tmp = block[6];
	block[6] = S1[block[14]];
	block[14] = S1[tmp];
	/* Row 3 */
	tmp = block[15];
	block[15] = S1[block[11]];
	block[11] = S1[block[7]];
	block[7] = S1[block[3]];
	block[3] = S1[tmp];

	/*
	 * MixColumns
	 */
	for (i = lastround; i < 16; i += 4) /* lastround = 16 if it is the last round, 0 otherwise */
	{
		uint8_t *column = block + i;
		uint8_t tmp2 = column[0];
		tmp = column[0] ^ column[1] ^ column[2] ^ column[3];

		column[0] ^= tmp ^ xtime1(column[0] ^ column[1]);
		column[1] ^= tmp ^ xtime1(column[1] ^ column[2]);
		column[2] ^= tmp ^ xtime1(column[2] ^ column[3]);
		column[3] ^= tmp ^ xtime1(column[3] ^ tmp2);
	}

	/*
	 * AddRoundKey
	 */
	for (i = 0; i < 16; i++)
	{
		block[i] ^= round_key[i];
	}
}

/*
 * Compute the @(round + 1)-th round key in @next_key, given the @round-th key in @prev_key
 * @round in {0...9}
 * The ``master key'' is the 0-th round key
 */
void next_aes128_round_key(const uint8_t prev_key[16], uint8_t next_key[16], int round)
{
	int i;

	next_key[0] = prev_key[0] ^ S[prev_key[13]] ^ RC[round];
	next_key[1] = prev_key[1] ^ S[prev_key[14]];
	next_key[2] = prev_key[2] ^ S[prev_key[15]];
	next_key[3] = prev_key[3] ^ S[prev_key[12]];

	for (i = 4; i < 16; i++)
	{
		next_key[i] = prev_key[i] ^ next_key[i - 4];
	}
}

void next_aes128_round_key1(const uint8_t prev_key[16], uint8_t next_key[16], int round)
{
	int i;

	next_key[0] = prev_key[0] ^ S1[prev_key[13]] ^ RC[round];
	next_key[1] = prev_key[1] ^ S1[prev_key[14]];
	next_key[2] = prev_key[2] ^ S1[prev_key[15]];
	next_key[3] = prev_key[3] ^ S1[prev_key[12]];

	for (i = 4; i < 16; i++)
	{
		next_key[i] = prev_key[i] ^ next_key[i - 4];
	}
}
/**************************************************************************************************/
/* 										 								                          */
/* 					                    Question 2                                                */
/* 										 								                          */
/**************************************************************************************************/
/*
 * Compute the @round-th round key in @prev_key, given the @(round + 1)-th key in @next_key
 * @round in {0...9}
 * The ``master decryption key'' is the 10-th round key (for a full AES-128)
 */
void prev_aes128_round_key(const uint8_t next_key[16], uint8_t prev_key[16], int round)
{ // prev is simply the opposite steps of next and the inverse of a xor is a xor so:
	int i;
	for (i = 4; i < 16; i++)
	{
		prev_key[i] = next_key[i] ^ next_key[i - 4];
	}
	prev_key[0] = next_key[0] ^ S[prev_key[13]] ^ RC[round - 1];
	prev_key[1] = next_key[1] ^ S[prev_key[14]];
	prev_key[2] = next_key[2] ^ S[prev_key[15]];
	prev_key[3] = next_key[3] ^ S[prev_key[12]];
}

void prev_aes128_round_key1(const uint8_t next_key[16], uint8_t prev_key[16], int round)
{ // prev is simply the oppiste steps of next and the inverse of a xor is a xor so:
	int i;
	for (i = 4; i < 16; i++)
	{
		prev_key[i] = next_key[i] ^ next_key[i - 4];
	}
	prev_key[0] = next_key[0] ^ S1[prev_key[13]] ^ RC[round - 1];
	prev_key[1] = next_key[1] ^ S1[prev_key[14]];
	prev_key[2] = next_key[2] ^ S1[prev_key[15]];
	prev_key[3] = next_key[3] ^ S1[prev_key[12]];
}

/*
 * Encrypt @block with @key over @nrounds. If @lastfull is true, the last round includes MixColumn, otherwise it doesn't.
 * @nrounds <= 10
 */
void aes128_enc(uint8_t block[AES_BLOCK_SIZE], const uint8_t key[AES_128_KEY_SIZE], unsigned nrounds, int lastfull)
{
	uint8_t ekey[32];
	int i, pk, nk;

	for (i = 0; i < 16; i++)
	{
		block[i] ^= key[i];
		ekey[i] = key[i];
	}
	next_aes128_round_key(ekey, ekey + 16, 0);

	pk = 0;
	nk = 16;
	for (i = 1; i < nrounds; i++)
	{
		aes_round(block, ekey + nk, 0);
		pk = (pk + 16) & 0x10;
		nk = (nk + 16) & 0x10;
		next_aes128_round_key(ekey + pk, ekey + nk, i);
	}
	if (lastfull)
	{
		aes_round(block, ekey + nk, 0);
	}
	else
	{
		aes_round(block, ekey + nk, 16);
	}
}

void aes128_enc1(uint8_t block[AES_BLOCK_SIZE], const uint8_t key[AES_128_KEY_SIZE], unsigned nrounds, int lastfull)
{
	uint8_t ekey[32];
	int i, pk, nk;

	for (i = 0; i < 16; i++)
	{
		block[i] ^= key[i];
		ekey[i] = key[i];
	}
	next_aes128_round_key1(ekey, ekey + 16, 0);

	pk = 0;
	nk = 16;
	for (i = 1; i < nrounds; i++)
	{
		aes_round(block, ekey + nk, 0);
		pk = (pk + 16) & 0x10;
		nk = (nk + 16) & 0x10;
		next_aes128_round_key1(ekey + pk, ekey + nk, i);
	}
	if (lastfull)
	{
		aes_round1(block, ekey + nk, 0);
	}
	else
	{
		aes_round1(block, ekey + nk, 16);
	}
}

uint8_t **intialisationMatrix(unsigned nb_ligne, unsigned nb_colonne, uint8_t cst, bool fl)
{
	uint8_t **matrix;
	if (!(matrix = malloc(nb_ligne * sizeof(uint8_t *))))
	{
		perror("No memory space ");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < nb_ligne; i++)
	{
		if (!(matrix[i] = malloc(nb_colonne * sizeof(uint8_t))))
		{
			perror("No memory space ");
			exit(EXIT_FAILURE);
		}
		for (int j = 0; j < nb_colonne; j++)
			matrix[i][j] = cst;
		if (fl)
		{
			matrix[i][0] = i;
		}
	}
	return matrix;
}

bool candidateValidation(uint8_t *matrix, unsigned size)
{
	int sum = 0;
	for (int i = 0; i < size; i++)
		sum ^= matrix[i];

	if (sum == 0)
		return 1;

	return 0;
}

void porentielkEY(uint8_t **block, uint8_t **keyGuess, uint8_t *key)
{
	/*
	 *				The goal is for each block of the key we will eleminate candidates from 256 possibility
	 *
	 */
	for (int ElmtKeyCandid = 0; ElmtKeyCandid < AES_BLOCK_SIZE; ElmtKeyCandid++) // each block of the matrix
	{

		for (int candidate = 0; candidate < 256; candidate++) // a candidate of the 256 possibility
		{
			if (keyGuess[ElmtKeyCandid][candidate]) // we just need to verify if the ancient candidate are still a candidate for the block key or not
			{
				uint8_t reversedBlocksElmt[256]; // this table will help us store the reverse state of the block EltKeyCandid in all the  											// Λ-set so that we can test if it validate the 3-round distinguisher(sum=0)

				for (int matrix = 0; matrix < 256; matrix++)
				{
					/*
					 * Reverse => AddRoundKey
					 */
					reversedBlocksElmt[matrix] = block[matrix][ElmtKeyCandid] ^ candidate; // subst the element key(candidate)
				}

				for (int matrix = 0; matrix < 256; matrix++)
				{
					/*
					 * Reverse => SubByte (dont need to ShiftRows we gonna reverse every element of the matrix  wich the position is the
					 * relatively the same on all matrixes)
					 */
					int index = reversedBlocksElmt[matrix];
					reversedBlocksElmt[matrix] = Sinv[index];
				}
				// Check if the element key is good by summing those values from the Λ-set and verifying if it is equal to 0
				if (!candidateValidation(reversedBlocksElmt, 256)) // So if it's not that's not a candidate so this block should not have
					keyGuess[ElmtKeyCandid][candidate] = 0;		   // So if it's not the case we will register it
				else
					key[ElmtKeyCandid] = candidate;
			}
		}
	}
}

void porentielkEY1(uint8_t **block, uint8_t **keyGuess, uint8_t *key)
{
	/*
	 *				The goal is for each block of the key we will eleminate candidates from 256 possibility
	 *
	 */
	for (int ElmtKeyCandid = 0; ElmtKeyCandid < AES_BLOCK_SIZE; ElmtKeyCandid++) // each block of the matrix
	{

		for (int candidate = 0; candidate < 256; candidate++) // a candidate of the 256 possibility
		{
			if (keyGuess[ElmtKeyCandid][candidate]) // we just need to verify if the ancient candidate are still a candidate for the block key or not
			{
				uint8_t reversedBlocksElmt[256]; // this table will help us store the reverse state of the block EltKeyCandid in all the  											// Λ-set so that we can test if it validate the 3-round distinguisher(sum=0)

				for (int matrix = 0; matrix < 256; matrix++)
				{
					/*
					 * Reverse => AddRoundKey
					 */
					reversedBlocksElmt[matrix] = block[matrix][ElmtKeyCandid] ^ candidate; // subst the element key(candidate)
				}

				for (int matrix = 0; matrix < 256; matrix++)
				{
					/*
					 * Reverse => SubByte (dont need to ShiftRows we gonna reverse every element of the matrix  wich the position is the
					 * relatively the same on all matrixes)
					 */
					int index = reversedBlocksElmt[matrix];
					reversedBlocksElmt[matrix] = Sinv1[index];
				}
				// Check if the element key is good by summing those values from the Λ-set and verifying if it is equal to 0
				if (!candidateValidation(reversedBlocksElmt, 256)) // So if it's not that's not a candidate so this block should not have
					keyGuess[ElmtKeyCandid][candidate] = 0;		   // So if it's not the case we will register it
				else
					key[ElmtKeyCandid] = candidate;
			}
		}
	}
}

bool falsepositive(uint8_t **keyGuess)
{
	int flag = 0;
	for (int j = 0; j < AES_BLOCK_SIZE; j++)
	{
		flag = 0;
		for (int i = 0; i < 256; i++)
		{
			if (keyGuess[j][i])
				flag++;
		}
		if (flag > 1)
			return 1;
	}
	return 0;
}
