#include "decrypt.h" 

// Fonction pour déchiffrer le payload avec un XOR simple
void decrypt(unsigned char* payload, size_t size, unsigned char key) {

    // Parcourt chaque octet du payload et applique un XOR avec la clé
    for (size_t i = 0; i < size; ++i) {
        payload[i] ^= key;
    }
}