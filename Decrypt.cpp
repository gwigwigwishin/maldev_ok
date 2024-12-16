#include "decrypt.h" 

// Fonction pour d�chiffrer le payload avec un XOR simple
void decrypt(unsigned char* payload, size_t size, unsigned char key) {

    // Parcourt chaque octet du payload et applique un XOR avec la cl�
    for (size_t i = 0; i < size; ++i) {
        payload[i] ^= key;
    }
}