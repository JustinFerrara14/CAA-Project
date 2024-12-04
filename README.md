# CAA-Project Ferrara Justin

## Niveau de sécurité choisi
Dans ce projet, j'ai choisi de partir sur un niveau de sécurité de 256 bits pour la cryptographie symétriques.

## Contraintes client
Le client dispose uniquement de son nom d'utilisateur et son mot de passe.

## Contraintes serveur

## Algorithmes utilisés
- OPAQUE pour dériver une clé symétrique du mot de passe et établir une connexion sécurisée avec le serveur
- AES-GCM pour le chiffrement des clés asymétriques.
- ECIES pour le chiffrement des messages
- EdDSA pour la signature des messages

## Gestion des clés
- Chaque utilisateur possède un mot de passe.
- Chaque utilisateur possède 1 clé asymétrique de 256 bits pour le chiffrement des messages (priv1, pub1).
- Chaque utilisateur possède 1 clé asymétrique de 256 bits pour la signature des messages (priv2, pub2).
- Chaque utilisateur possède 1 paire de clés asymétrique de 256 bits pour la communication avec le serveur (priv3, pub3).

## Tailles des clés
- La sortie de OPAQUE pour la clé symétrique est de 768 bits, avec un sel de 128 bits aléatoire, pour pouvoir générer un hash de 512 bits et une clé de chiffrement de 256 bits.
- La deuxième sortie de OPAQUE est une paire de clé asymétrique de ??????? bits.
- AES-GCM utilise une clé de 256 bits, avec un sel de 96 bits aléatoire.
- ECIES utilise une des paires de clés asymétriques de 256 bits, avec r aléatoire.
- EdDSA utilise une des paires clés asymétriques de 256 bits. ?????????


## Possession des clés

## Modélisation des adversaires
- Le système doit être protégé contre les adversaires actifs
- Les messages envoyé doivent être non répudiables
- Le serveur est honnête mais curieux
## Légendes
- utilisateur : personne physique utilisant la machine
- client : ordinateur, machine que l'utilisateur utilise
- serveur : serveur
## Création de compte
- L'utilisateur renseigne un nom d'utilisateur et un mot de passe.
- Le client vérifie que le mot de passe est assez fort, si ce n'est pas le cas, il demande un nouveau mot de passe.
- Le client génère un sel aléatoire de 128 bits.
- Le client calcule :

$$
(k, h) = Argon2id(password, salt)
$$

- Le client génère 2 clés asymétriques de 256 bits 
$$
priv1 = random[0..255]
$$
$$
pub1 = priv1*G
$$
$$
priv2 = random[0..255]
$$
$$
pub2 = priv2*G
$$
- Le client chiffre priv1 et priv2 avec AES-GCM en utilisant sa clé k, ce qui donne : ?????
$$
IV1 = random[0..95]
$$
$$
cpriv1||tag1 = AES\_GCM_k(IV1, priv1)
$$
$$
IV2 = random[0..95]
$$$$
cpriv2||tag2 = AES\_GCM_k(IV2, priv2)
$$
- Le client envoie au serveur:
	- nom d'utilisateur
	- sel
	- h
	- cpriv1 || tag1 || IV1
	- pub1
	- cpriv2 || tag2 || IV2
	- pub2

## Login
- Le client renseigne son nom d'utilisateur et son mot de passe.
- Le client envoie son nom d'utilisateur au serveur et le serveur lui renvoie le sel associé.
- Le client calcule :
$$
(k', h') = Argon2id(password, salt)
$$
- Le client envoie h' au serveur.
- Le serveur compare h' avec h, si c'est les même il continue. Sinon l'authentififaction à échoué.
- Le serveur renvoie (cpriv1, pub1, cpriv2, pub2) au client.
- Le client déchiffre cpriv1 et cpriv2 avec AES-GCM :
$$
priv1 = AES\_GCM_k(cpriv1||tag1||IV1)
$$
$$
priv2 = AES\_GCM_k(cpriv2||tag2||IV2)
$$
- Le client contrôle que tag1 et tag2 sont correct
- Le client contrôle cette égalité pour s'assurer que la clé publique n'a pas été modifiée :
$$
priv1 * G = pub1
$$
## Changement de mot de passe
- Le client fait un login normal.
- Le client possède donc (priv1, pub1, priv2, pub2, k, h).
- L'utilisateur renseigne son nouveau mot de passe.
- Le client génère un nouveau sel aléatoire de 128 bits.
- Le client calcule : $$
(newK, newH) = Argon2id(newPassword, newSalt)
$$
- Le client chiffre priv1 et priv2 avec AES-GCM et newK :
$$
IV1 = random[0..95]
$$$$
cpriv1||tag1 = AES\_GCM_{newK}(IV1, priv1)
$$$$
IV2 = random[0..95]
$$$$
cpriv2||tag2 = AES\_GCM_{newK}(IV2, priv2)
$$
- Le client envoie au server :
	- nom d'utilisateur
	- h
	- nouveau sel
	- newH
	- pub1
	- pub2
	- cpriv1
	- cpriv2


## Envoi de message
- Le client fait un login normal.
- Le client possède donc (priv1, pub1, priv2, pub2, k, h).
- Le client demande la clé publique du destinataire du message au serveur pub1Dest.
- Le client utilise ECIES pour chiffrer le message en utilisant la clé publique du destinataire :
$$
r = random
$$
$$
R\ ||\ c\ ||\ T = ECIES(pub1Dest, message, r)
$$
- Le client signe le message complet et la date autorisée d'ouverture du message avec priv2
$$
k = random
$$
$$
(r,s) = EcDSA_{priv2}(priv2, R||c||T||date)
$$
- Le client vérifie si la signature est correcte
- Le client envoie au serveur :
$$
R\ ||\ c\ ||\ T\ ||\ date\ ||\ r\ ||\ s
$$

## Réception de message
- Le client fait un login normal.
- Le client possède donc (priv1, pub1, priv2, pub2, k, h).
- Le client reçoit du serveur :
$$
c\ ||\ T\ ||\ date\ ||\ r\ ||\ s
$$
- Quand la date est atteinte, le client reçoit du serveur :
$$
R\ ||\ c\ ||\ T\ ||\ date\ ||\ r\ ||\ s
$$
- Le client vérifie que la signature du message est correcte
- Le client déchiffre le message m :
$$
m = ECIES(priv1, R||c||T)
$$
## Types d'adversaires
- **Adversaires Actifs** :   
  - **Signatures Numériques** : Les messages sont signés avec les clés privées des utilisateurs, empêchant ainsi la répudiation et garantissant l'authenticité des messages.  
  - **Utilisation de TLS 1.3** : Toutes les communications entre le client et le serveur sont sécurisées avec TLS 1.3, protégeant les données en transit contre les interceptions et les modifications.  
- **Serveur Honnête mais Curieux** :   
  -  **Chiffrement de Bout en Bout** : Les messages sont chiffrés de bout en bout avec ECIES, garantissant que seuls les destinataires prévus peuvent les déchiffrer.  
  - **Stockage Sécurisé des Clés** : Les clés privées des utilisateurs sont stockées chiffrées sur le serveur, empêchant l'accès non autorisé même en cas de compromission du serveur  
  - **Authentification Forte** : Utilisation de Argon2 pour le hachage des mots de passe, garantissant une résistance aux attaques par force brute.