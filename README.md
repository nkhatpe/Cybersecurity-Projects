# Operating Systems & Cybersecurity Projects

This repository contains implementations of three major projects focusing on operating system internals and cryptographic security.

## Project Directory Structure
```
.
├── proj1-rc6/           # RC6 Block Cipher Implementation
├── proj2-blowfish/      # Blowfish with OpenSSL
└── proj3-buffer/        # Buffer Overflow Analysis
```

## Project 1: RC6 Block Cipher Implementation

### Description
Implementation of the RC6 block cipher, a symmetric key block cipher designed as a successor to RC5. Focused on implementing the core encryption/decryption functionalities as described in the RC6 specification.

### Features
- Complete RC6 encryption and decryption
- Support for variable key sizes
- Word-oriented processing using 32-bit operations
- Configurable number of rounds (default 20)
- Data-dependent rotations and quadratic function for mixing

### Technical Implementation
- Basic primitive operations (add, subtract, multiply, XOR)
- Data-dependent rotations
- Key scheduling algorithm
- Test vectors for validation

## Project 2: Blowfish Implementation

### Description
Integration of the Blowfish cipher using OpenSSL library to provide encryption and decryption functionality.

### Features
- Block cipher mode: CBC
- Block size: 64 bits
- Key size: 128 bits
- Padding scheme: Length of pad in padded characters

### Components
```c
// Core functions implemented
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);
```

### Usage
- Encryption handles dynamic input sizes with appropriate padding
- Decryption validates and removes padding
- Memory management with proper allocation/deallocation

## Project 3: Buffer Overflow Exploitation

### Description
Educational project demonstrating buffer overflow vulnerabilities and developing a practical exploit.

### Components
- Vulnerable C program demonstration
- Attack string generator
- Security analysis report

### Security Considerations
- Stack protection disabled for demonstration
- ASLR disabled in testing environment
- Execution on 32-bit system
- Non-executable stack protection disabled

### Implementation Details
```c
// Vulnerable program components
void confuse() {...}
void prompt() {...}
void target() {...}
```

## Security Notice
These implementations are for educational purposes only. The buffer overflow project should only be run in a controlled, isolated environment.

## Author
Narendra Khatpe  
State University of New York at Binghamton  
narendrakhatpe@gmail.com
