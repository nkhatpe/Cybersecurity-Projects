Narendra Khatpe

nkhatpe@binghamton.edu

Tested on remote

==================================================================================================================

How to build and run program?

make

rc6_custom executable will be generated

./rc6_custom input.txt output.txt

==================================================================================================================

The RC6 is implemented as per given condition i.e. RC6-w/r/b, where w = 32, and r = 20 


input.txt file includes three main things

[mode]     either Encryption or Decryption
[message type and message] 
[userkey]


Output.txt

[Encrypted or Decrypted message along with its type]

==================================================================================================================

Important Instruction about the input file: 

I have used ':' for message type and userkey in order to separate the message and key. 
hence while testing please do not forget to include the ':' after plaintext or ciphertext i.e. message type and userkey 


if the format of input file is wrong program will not work



