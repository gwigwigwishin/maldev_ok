# Recap
## **Structure du Projet**

|**Fichier/Dossier**|**Description**|
|---|---|
|`main.cpp`|Code source principal du loader.|
|`server.py`|Script Python servant le shellcode chiffré.|
|`README.md`|Instructions d'utilisation (ce fichier).|

## **Résumé des Objectifs Réalisés**

|**Objectif**|**Statut**|
|---|---|
|Injection de shellcode dans un processus distant|✅ Réalisé|
|Utilisation exclusive de l'API Windows|✅ Réalisé|
|Pas d'appel à des fonctions comme printf, scanf, malloc, free, strcpy, memcpy|✅ Réalisé|
|Téléchargement du shellcode depuis un serveur Web Python|✅ Réalisé|
|La page mémoire où le shellcode est injectée a les permissions RX|✅ Réalisé|
|README explicatif|✅ Réalisé|
|Pas de Warnings a la compilation|✅ Réalisé|
|Les variables allouées avec LocalAlloc sont libérées|✅ Réalisé|

|**Points Bonus**|**Statut**|
|---|---|
|GetModuleHandle & GetProcAddress Masking|✅ Fait|
|Custom GetModuleHandle & GetProcAddress|✅ Fait (+2)|
|API Hashing|❌ Pas fait|
|---|---|
|RC4 Encryption|❌ Pas fait|
|---|---|
|Random Key on Download|✅ Fait (+2)|
|---|---|
|Injection via PID|✅ Fait|
|Injection via Process Name|✅ Fait (+2)|
|---|---|
|Overwrite Shellcode Buffer with Zeros|✅ Fait (+1)|
|---|---|
|Use NTDLL Functions|❌ Pas fait|
|---|---|
|Alternative Injection Methods (APC, etc.)|❌ Pas fait|
|---|---|
|Other Relevant Features|❌ Pas fait|



# Etape 1 : Serveur HTTP et chiffrement du shellcode
Fichiers : HTTPClient.h, HTTPClient.cpp

# Etape 2 : Récupération du shellcode chiffré
Premier main avec les fonctions....

# Etape 3 : Déchiffrement du shellcode
Fichiers : decrypt.h, decrypt.cpp
Mise à jour de main avec les fonctions...

# Etape 4 : Injection dans un processus local
Fichiers : ...
Mise à jour de main avec les fonctions....

# Bonus numéro uno : Clé aléatoire (serveur web)
Fichier : http_server.py
Mise à jour de la fonction

# Bonus numéro dos : Masquer l'appel aux fonctions de WinAPI
Fichier : Memory.cpp
Mise à jour du fichier
