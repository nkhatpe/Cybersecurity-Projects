#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <iostream>
#include <string>

using namespace std;

#include "fscrypt.h"

// Function to print hexadecimal representation of a single character buffer
void PrintChar(string name, unsigned char* buffer) {
    cout << name << ": ";
    for (int i = 0; i < BLOCKSIZE; i++) {
        printf("%02x ", (unsigned char) *(buffer + i));
    }
    printf("\n");
}

// Function to print hexadecimal representation of a buffer of a given size
void PrintBuffer(string name, unsigned char* buffer, int size) {
    cout << name << ": " << size << " bytes" << endl;
    for (int i = 0; i < size; i++) {      
        if (i % BLOCKSIZE == 0 && i != 0) printf("\n");
        printf("%02x ", (unsigned char) buffer[i]);
    }
    printf("\n");
}

// Function to print a matrix of buffers
void PrintBufferMatrix(string name, unsigned char** buffer, int blockCount) {
    cout << name << endl;
    for (int i = 0; i < blockCount; i++) {
        printf("block %i: ", i);
        for (int j = 0; j < BLOCKSIZE; j++) {   
            printf("%02x ", (unsigned char) buffer[i][j]);
        }
        printf("\n");
    }
}

// Function to calculate the length of a null-terminated character array
int GetKeyLength(char* keyStr) {
    int length = 0;
    while (keyStr[length]) {
        length++;
    }
    return length;
}

// Encryption function
void* fs_encrypt(void* plaintext, int bufferSize, char* keyStr, int* resultLength) {
    printf("fs_encrypt()\n");
    PrintBuffer("plaintext", (unsigned char*) plaintext, bufferSize);
    int keyLength = GetKeyLength(keyStr);
    PrintBuffer("key", (unsigned char*) keyStr, keyLength);

    // Initialize Blowfish key
    BF_KEY key;
    BF_set_key(&key, keyLength, (unsigned char*) keyStr);

    // Initialization vector (IV) containing NULL characters
    unsigned char* iv = new unsigned char[BLOCKSIZE];
    memset(iv, 0, BLOCKSIZE);

    // Padding calculation
    int padN = (floor(bufferSize / BLOCKSIZE) + 1) * BLOCKSIZE - bufferSize;
    int blockCount = (bufferSize + padN) / BLOCKSIZE;

    // Allocate memory for blocks
    unsigned char** blocks = new unsigned char*[blockCount];
    for (int i = 0; i < blockCount; i++) {
        blocks[i] = new unsigned char[BLOCKSIZE];
        // Copy plaintext to blocks
        for (int j = 0; j < BLOCKSIZE; j++) {        
            if (BLOCKSIZE * i + j > bufferSize) break;
            memcpy(blocks[i] + j, (unsigned char*) plaintext + BLOCKSIZE * i + j, 1);
        }
    }
    // Padding
    for (int i = 0; i < padN; i++) {
        blocks[blockCount - 1][(BLOCKSIZE - 1) - i] = padN;
    }   

    // XOR first block with IV and encrypt
    *blocks[0] ^= *iv;
    BF_ecb_encrypt(blocks[0], blocks[0], &key, BF_ENCRYPT);

    // CBC mode encryption for subsequent blocks
    for (int i = 1; i < blockCount; i++) {  
        *blocks[i] ^= *blocks[i - 1];
        BF_ecb_encrypt(blocks[i], blocks[i], &key, BF_ENCRYPT);
    }
    PrintBufferMatrix("encrypted", blocks, blockCount);

    // Copy encrypted blocks to result buffer
    unsigned char* result = new unsigned char[blockCount * BLOCKSIZE]; 
    for (int i = 0; i < blockCount; i++) {
        memcpy(result + i * BLOCKSIZE, blocks[i], BLOCKSIZE);
    }

    // Cleanup
    for (int i = 0; i < blockCount; i++) {
        delete[] blocks[i];
    }
    delete[] blocks;
    delete[] iv;

    // Set result length
    *resultLength = blockCount * BLOCKSIZE;   
    return result;
}

// Decryption function
void* fs_decrypt(void* ciphertext, int bufferSize, char* keyStr, int* resultLength) {
    printf("fs_decrypt()\n");
    PrintBuffer("ciphertext", (unsigned char*) ciphertext, bufferSize);
    int keyLength = GetKeyLength(keyStr);
    PrintBuffer("key", (unsigned char*) keyStr, keyLength);

    // Initialize Blowfish key
    BF_KEY key;
    BF_set_key(&key, keyLength, (unsigned char*) keyStr);

    // Initialization vector (IV) containing NULL characters
    unsigned char* iv = new unsigned char[BLOCKSIZE];
    memset(iv, 0, BLOCKSIZE);

    // Calculate number of blocks
    int blockCount = (bufferSize) / BLOCKSIZE;

    // Allocate memory for blocks
    unsigned char** blocks = new unsigned char*[blockCount];
    for (int i = 0; i < blockCount; i++) {
        blocks[i] = new unsigned char[BLOCKSIZE];
        // Copy ciphertext blocks
        for (int j = 0; j < BLOCKSIZE; j++) {        
            memcpy(blocks[i], (unsigned char*) ciphertext + BLOCKSIZE * i, BLOCKSIZE);
        }
    }

    // CBC mode decryption
    for (int i = blockCount - 1; i > 0; i--) {  
        BF_ecb_encrypt(blocks[i], blocks[i], &key, BF_DECRYPT);
        *blocks[i] ^= *blocks[i - 1];
    }   
    BF_ecb_encrypt(blocks[0], blocks[0], &key, BF_DECRYPT);
    *blocks[0] ^= *iv;

    // Padding removal
    int padN = blocks[blockCount - 1][BLOCKSIZE - 1];
    char truePad = 1;
    for (int i = BLOCKSIZE - 1; i > BLOCKSIZE - padN; i--) {
        if (blocks[blockCount - 1][i] != padN) {
            truePad = 0;    
            break;
        }
    }

    // Set result length
    if (truePad) *resultLength = bufferSize - padN;
    else *resultLength = bufferSize;

    // Copy decrypted data to result buffer
    unsigned char* result = new unsigned char[*resultLength]; 
    for (int i = 0; i < blockCount; i++) {
        for (int j = 0; j < BLOCKSIZE; j++) {
            if (BLOCKSIZE * i + j >= *resultLength) break;
            memcpy(result + i * BLOCKSIZE + j, blocks[i] + j, 1);
        }
    }

    // Cleanup
    for (int i = 0; i < blockCount; i++) {
        delete[] blocks[i];
    }
    delete[] blocks;
    delete[] iv;

    // Print decrypted data
    PrintBuffer("decrypted", result, *resultLength);
    return result;
}

