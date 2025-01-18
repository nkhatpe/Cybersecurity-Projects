#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

// Encryption and Decryption modes
#define ENCRYPT_MODE 1
#define DECRYPT_MODE 0

// Word size and number of rounds for RC6 algorithm as per specified condition
#define WORD_SIZE 32
#define NUM_ROUNDS 20


// Indexes for the four registers in the RC6 algorithm
#define REG_A_INDEX 0
#define REG_B_INDEX 1
#define REG_C_INDEX 2
#define REG_D_INDEX 3


// Array to hold the four registers during encryption/decryption
uint32_t registers[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};


// Mode of operation (encryption or decryption)
char mode = ENCRYPT_MODE;

// Array to store the user key and its size
unsigned char* key = NULL;
int keySize = 0;


// Array to hold the input text and its size
unsigned char* text = NULL;
int textSize = 0;


// Array to hold the round keys generated for RC6 algorithm
uint32_t roundKeys[2 * NUM_ROUNDS + 4];

// User key with zero padding in array format, little-endian format
uint32_t* userKey;
uint32_t userKeySize;


// Constants used in RC6 algorithm
const uint32_t P_CONSTANT = 0xB7E15163;
const uint32_t Q_CONSTANT = 0x9E3779B9;


// Function to parse input from a file
void readInput(char* filename) {

    // File pointer for input file
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error opening input file.\n");
        exit(1);
    }

    // Read the action mode (encryption/decryption) from input file
    char buffer;
    fread(&buffer, 1, 1, file);
    if (buffer == 'E' || buffer == 'e')
        mode = ENCRYPT_MODE;
    else if (buffer == 'D' || buffer == 'd')
        mode = DECRYPT_MODE;
    else {
        printf("Invalid action mode.\n");
        exit(1);
    }

    // Parse input text from the input file
    // This section reads the input text in hexadecimal format
    // and converts it into a byte array
    // Similarly, it reads the user key in hexadecimal format
    // and converts it into a byte array and then into a user key array
    while (buffer != ':') {
        fread(&buffer, 1, 1, file);
    }
    char* hexString = (char*)malloc(256);
    memset(hexString, 0, 256);
    int hexSize = 0;

    while (buffer != '\n') {
        fread(&buffer, 1, 1, file);
        if (buffer == ' ' || buffer == '\n')
            continue;
        hexString[hexSize] = buffer;
        hexSize++;
    }

    char* position = hexString;
    text = (unsigned char*)malloc(256);
    memset(text, 0, 256);
    textSize = 0;
    for (int i = 0; i < hexSize / 2; i++) {
        sscanf(position, "%2hhx", &text[i]);
        position += 2;
        textSize++;
    }

    if (textSize > WORD_SIZE / 8 * 4) {
        printf("Text size exceeds limit.\n");
        exit(1);
    }

    while (buffer != ':') {
        fread(&buffer, 1, 1, file);
    }
    memset(hexString, 0, 256);
    hexSize = 0;

    while (buffer != '\n') {
        fread(&buffer, 1, 1, file);
        if (buffer == ' ' || buffer == '\n')
            continue;
        hexString[hexSize] = buffer;
        hexSize++;
    }
    position = hexString;
    key = (unsigned char*)malloc(256);
    memset(key, 0, 256);
    keySize = 0;
    userKey = (uint32_t*)malloc(256 * sizeof(uint32_t));
    memset(userKey, 0, 256 * sizeof(uint32_t));

    uint32_t mask;
    for (int i = 0; i < hexSize / 2; i++) {
        sscanf(position, "%2hhx", &key[i]);
        mask = 0x00000000;
        mask |= key[i];
        mask = mask << (8 * (i % 4));
        userKey[(int)floor(i / 4)] |= mask;
        position += 2;
        keySize++;
    }
    
    // Close the input file
    fclose(file);
    userKeySize = ceil((float)keySize / (WORD_SIZE / 8));
}


// Function to write output to a file
void writeOutput(char* filename) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        printf("Error opening output file.\n");
        return;
    }
    
    // Write the ciphertext or plaintext to the output file
    // based on the action mode (encryption/decryption)
    if (mode == ENCRYPT_MODE) {
        fputs("ciphertext: ", file);
    } else {
        fputs("plaintext: ", file);
    }
    for (int regIndex = 0; regIndex < 4; regIndex++) {
        uint32_t mask;
        unsigned char value;
        for (int i = 0; i < WORD_SIZE / 8; i++) {
            mask = registers[regIndex] >> i * 8;
            value = mask & ~(0xFFFFFF00);
            if (regIndex == 3 && i == WORD_SIZE / 8 - 1) {
                fprintf(file, "%02x\n", value);
            } else {
                fprintf(file, "%02x ", value);
            }
        }
    }
    
    // Close the output file
    fclose(file);
}


// Function to perform left rotation on a 32-bit integer
uint32_t rotateLeft(uint32_t a, uint32_t b) {

    // Perform left rotation by b bits on integer a
    uint32_t shiftCount = b & ~(0xFFFFFFE0);
    uint32_t mask;
    for (uint32_t i = 0; i < shiftCount; i++) {
        mask = (a & ~(0x7FFFFFFF)) >> (WORD_SIZE - 1);
        a = a << 1;
        a |= mask;
    }
    
    // Retun the result
    return a;
}

uint32_t rotateRight(uint32_t a, uint32_t b) {
    uint32_t shiftCount = b & ~(0xFFFFFFE0);
    uint32_t mask;
    for (uint32_t i = 0; i < shiftCount; i++) {
        mask = (a & ~(0xFFFFFFFE)) << (WORD_SIZE - 1);
        a = a >> 1;
        a |= mask;
    }
    return a;
}

// Function to generate round keys for RC6 algorithm

void generateRoundKeys() {

    // Generate round keys based on the user key
    // using the RC6 key schedule algorithm
    roundKeys[0] = P_CONSTANT;
    for (uint32_t i = 1; i <= 2 * NUM_ROUNDS + 3; i++) {
        roundKeys[i] = roundKeys[i - 1] + Q_CONSTANT;
    }
    uint32_t indexI = 0, indexJ = 0, registerA = 0, registerB = 0;
    uint32_t max = 2 * NUM_ROUNDS + 4;
    if (userKeySize > max)
        max = userKeySize;
    uint32_t v = 3 * max;
    for (uint32_t s = 1; s <= v; s++) {
        roundKeys[indexI] = rotateLeft(roundKeys[indexI] + registerA + registerB, 3);
        registerA = roundKeys[indexI];
        userKey[indexJ] = rotateLeft(userKey[indexJ] + registerA + registerB, registerA + registerB);
        registerB = userKey[indexJ];
        indexI = (indexI + 1) % (2 * NUM_ROUNDS + 4);
        indexJ = (indexJ + 1) % userKeySize;
    }
}

// Function to partition input text into four registers
void partitionInputText(unsigned char* text) {

    // Partition the input text into four registers
    uint32_t mask;
    int wordBytes = WORD_SIZE / 8;
    for (int i = 0; i < textSize; i++) {
        mask = 0x00000000;
        mask |= text[i];
        mask = mask << (8 * (i % wordBytes));
        registers[(int)floor(i / wordBytes)] |= mask;
    }
}

// Function to encrypt the input text using RC6 algorithm
void encryptText() {

    // Encrypt the input text using RC6 algorithm
    registers[REG_B_INDEX] = registers[REG_B_INDEX] + roundKeys[0];
    registers[REG_D_INDEX] = registers[REG_D_INDEX] + roundKeys[1];
    uint32_t logw = log2(WORD_SIZE);
    for (int i = 1; i <= NUM_ROUNDS; i++) {
        uint32_t t = rotateLeft(registers[REG_B_INDEX] * (2 * registers[REG_B_INDEX] + 1), logw);
        uint32_t u = rotateLeft(registers[REG_D_INDEX] * (2 * registers[REG_D_INDEX] + 1), logw);
        registers[REG_A_INDEX] = rotateLeft(registers[REG_A_INDEX] ^ t, u) + roundKeys[2 * i];
        registers[REG_C_INDEX] = rotateLeft(registers[REG_C_INDEX] ^ u, t) + roundKeys[2 * i + 1];
        uint32_t oldRegisters[4];
        oldRegisters[REG_A_INDEX] = registers[REG_A_INDEX];
        oldRegisters[REG_B_INDEX] = registers[REG_B_INDEX];
        oldRegisters[REG_C_INDEX] = registers[REG_C_INDEX];
        oldRegisters[REG_D_INDEX] = registers[REG_D_INDEX];
        registers[REG_A_INDEX] = oldRegisters[REG_B_INDEX];
        registers[REG_B_INDEX] = oldRegisters[REG_C_INDEX];
        registers[REG_C_INDEX] = oldRegisters[REG_D_INDEX];
        registers[REG_D_INDEX] = oldRegisters[REG_A_INDEX];
    }
    registers[REG_A_INDEX] = registers[REG_A_INDEX] + roundKeys[2 * NUM_ROUNDS + 2];
    registers[REG_C_INDEX] = registers[REG_C_INDEX] + roundKeys[2 * NUM_ROUNDS + 3];
}


// Function to decrypt the input text using RC6 algorithm
void decryptText() {

    // Decrypt the input text using RC6 algorithm
    registers[REG_C_INDEX] = registers[REG_C_INDEX] - roundKeys[2 * NUM_ROUNDS + 3];
    registers[REG_A_INDEX] = registers[REG_A_INDEX] - roundKeys[2 * NUM_ROUNDS + 2];
    uint32_t logw = log2(WORD_SIZE);
    for (uint32_t i = NUM_ROUNDS; i >= 1; i--) {
        uint32_t oldRegisters[4];
        oldRegisters[REG_A_INDEX] = registers[REG_A_INDEX];
        oldRegisters[REG_B_INDEX] = registers[REG_B_INDEX];
        oldRegisters[REG_C_INDEX] = registers[REG_C_INDEX];
        oldRegisters[REG_D_INDEX] = registers[REG_D_INDEX];
        registers[REG_A_INDEX] = oldRegisters[REG_D_INDEX];
        registers[REG_B_INDEX] = oldRegisters[REG_A_INDEX];
        registers[REG_C_INDEX] = oldRegisters[REG_B_INDEX];
        registers[REG_D_INDEX] = oldRegisters[REG_C_INDEX];
        uint32_t u = rotateLeft(registers[REG_D_INDEX] * (2 * registers[REG_D_INDEX] + 1), logw);
        uint32_t t = rotateLeft(registers[REG_B_INDEX] * (2 * registers[REG_B_INDEX] + 1), logw);
        registers[REG_C_INDEX] = rotateRight(registers[REG_C_INDEX] - roundKeys[2 * i + 1], t) ^ u;
        registers[REG_A_INDEX] = rotateRight(registers[REG_A_INDEX] - roundKeys[2 * i], u) ^ t;
    }
    registers[REG_D_INDEX] = registers[REG_D_INDEX] - roundKeys[1];
    registers[REG_B_INDEX] = registers[REG_B_INDEX] - roundKeys[0];
}


// Main function
int main(int argc, char* argv[]) {
    
    // Check if the correct number of command-line arguments is provided
    if (argc != 3) {
        printf("./rc6_custom <input.txt> <output.txt>\n");
        exit(1);
    }
    //printf("RC6 Algorithm 32/20/b: ");
    // Read input from input file
    readInput(argv[1]);
    
    // Generate round keys based on the user key
    generateRoundKeys();
    
    // Partition the input text into four registers
    partitionInputText(text);
    
    // Perform encryption or decryption based on the action mode
    if (mode == ENCRYPT_MODE)
        encryptText();
    else
        decryptText();
        
    // Write the output to the output file
    writeOutput(argv[2]);
    return 0;
}

