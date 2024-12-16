#include "decrypt.h" 

void decrypt(unsigned char* payload, size_t size, unsigned char key) {

    for (size_t i = 0; i < size; ++i) {
        payload[i] ^= key; // Applique un XOR pour chaque octet 

    }

}