# CAA-Project Ferrara Justin

## Niveau de sécurité choisi
Dans ce projet, j'ai choisi de partir sur un niveau de sécurité de 256 bits pour la cryptographie symétriques:
- cryptographie symétrique: 256 bits
- Hash : 512 bits
- Taille clés pour courbes elliptiques : 512 bits

## Contraintes client
Le client dispose uniquement de son nom d'utilisateur et son mot de passe.

## Contraintes serveur

## Algorithmes utilisés
- OPAQUE pour obtenir 2 clé symétrique. Une dérivée du mot de passe nommée `key` et une partagée avec le serveur pour établir une communication sécurisée nommée `key_communication`
- XSalsa20 avec Poly1305 comme mac pour le chiffrement symétrique des clés asymétriques. Cette combinaison d'algorithme sera nommée `SymEnc` ou `SymDec`
- X25519, XSalsa20 et Poly1305 pour le chiffrement hybride et la signature des certaines parties du message. Cette combinaison d'algorithme sera nommée `HybEnc` ou `HybDec`
- EdDSA pour la signature du message complet.

## Gestion des clés
- Chaque utilisateur possède un mot de passe.
- Chaque utilisateur possède 1 clé asymétrique de 256 bits pour le chiffrement des messages (priv1, pub1).
- Chaque utilisateur possède 1 clé asymétrique de 256 bits pour la signature des messages (priv2, pub2).
- Chaque utilisateur possède 1 clé symétrique de 256 bits pour la communication avec le serveur, cette clés est donnée à la fin de OPAQUE.

## Tailles des clés
- La sortie de OPAQUE pour la clé symétrique est de 768 bits, avec un sel de 128 bits aléatoire, pour pouvoir générer un hash de 512 bits et une clé de chiffrement de 256 bits.
- La deuxième sortie de OPAQUE est une paire de clé symétrique de ??????? bits.
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
- L'utilisateur renseigne un nom d'utilisateur et 2 mot de passe identiques.
- Le client vérifie que le premier mot de passe est le même que le second, si ce n'est pas le cas, il redemande un mot de passe.
- Le client fait un échange OPAQUE avec le serveur :

$$
Client:
client\_registration\_start\_result = OPAQUE_{ClientRegistration}(password)
$$
$$
Server:
server\_registration\_start\_result  = OPAQUE_{ServerRegistration}(username, client\_registration\_start\_result)
$$
$$
Client: client\_registration\_finish\_result = OPAQUE_{ClientRegistrationFinish}(password, server\_registration\_start\_result)
$$
$$
Client: key = client\_registration\_finish\_result.export\_key
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
- Le client chiffre priv1 et priv2 avec `SymEnc` en utilisant sa clé k, ce qui donne :
$$
IV1 = random[0..95]
$$
$$
cpriv1||tag1 = SymEnc_{key}(IV1, priv1)
$$
$$
IV2 = random[0..95]
$$$$
cpriv2||tag2 = SymEnc_{key}(IV2, priv2)
$$
- Le client termine l'échange OPAQUE en envoyant également les clés asymétriques : 
$$
Server:
password\_file  = OPAQUE_{ServerRegistrationFinish}(username, client\_registration\_finish\_result, cpriv1 || tag1 || IV1, pub1, cpriv2 || tag2 || IV2, pub2)
$$
- Le serveur associe `password_file` avec le username et les clés asymétrique uniquement si l'échange OPAQUE a réussi.
- Si il existe déjà un username dans la base de donnée, le server refuse d'écrire `password_file`
## Login
- Le client renseigne son nom d'utilisateur et son mot de passe.
- Le client fait un échange OPAQUE avec le serveur :
$$
Client:
client\_login\_start\_result = OPAQUE_{ClientLogin}(password)
$$
- Le serveur va chercher le password file en lien avec le username
$$
Server:
server\_login\_start\_result  = OPAQUE_{ServerLogin}(username, client\_login\_start\_result, password\_file)
$$
$$
Client: client\_login\_finish\_result = OPAQUE_{ClientLoginFinish}(password, server\_Login\_start\_result)
$$
$$
Client: key = client\_login\_finish\_result.export\_key\_key
$$
$$
Client: key\_communication = client\_login\_finish\_result.session\_key
$$
$$
Server:
server\_login\_finish\_result = OPAQUE_{ServerLoginFinish}(username, client\_login\_finish\_result)
$$
$$
Server: key\_communication = server\_login\_finish\_result.session\_key
$$
- Le serveur renvoie (cpriv1, pub1, cpriv2, pub2) au client à la fin de la connexion OPAQUE si la connexion a réussi.
- Le client déchiffre cpriv1 et cpriv2 avec SymDec :
$$
priv1 = SymDec_{key}(cpriv1||tag1||IV1)
$$
$$
priv2 = SymDec_{key}(cpriv2||tag2||IV2)
$$
- Le client contrôle que tag1 et tag2 sont correct
- Le client contrôle cette égalité pour s'assurer que la clé publique n'a pas été modifiée :
$$
priv1 * G = pub1
$$
- Le client possède donc :
	- key
	- key_communication
	- priv1
	- pub1
	- priv2
	- pub2
## Changement de mot de passe
- Le client fait un login normal.
- Le client possède donc (priv1, pub1, priv2, pub2, key, key_communication).
- L'utilisateur renseigne son nouveau mot de passe.
- Le client fait un échange OPAQUE comme dans registration avec le serveur :
$$
newKey = OPAQUE_{register}
$$
- Le client chiffre priv1 et priv2 avec SymEnc et newKey :
$$
IV1 = random[0..95]
$$$$
cpriv1||tag1 = SymEnc_{newKey}(IV1, priv1)
$$$$
IV2 = random[0..95]
$$$$
cpriv2||tag2 = SymEnc_{newKey}(IV2, priv2)
$$
- Le client envoie au server les nouvelles clés comme dans la partie registration `ServerFinishRegistration`.

> On notera que comme l'utilisateur existe déjà dans la base de données, le serveur vérifie que l'utilisateur est bien en possession de la clé key_communiction en vérifiant le MAC :
$$

auth = MAC_{key\_communication}(username)
$$
- Si le MAC est juste, alors le serveur accepte de changer le `password_file` dans la base de données, à la fin de l'échange dans server_registration_finish.

## Envoi de Message
- Le client fait un login normal.
- Le client possède donc (priv1, pub1, priv2, pub2, key, key_communication)
- L'utilisateur rentre le destinataire, le fichier à envoyer et le timestamp auquel le destinataire pourra l'ouvrir.
- Le client génére un le MAC :
$$
auth = MAC_{key\_communication}(username)
$$
- Le client demande la clé publique du destinataire du Message au serveur en envoyant son username et le MAC.
- Le serveur vérifie le MAC avec sa clé key_communication et renvoie la clé publique correspondante pub1Dest.
- Le client utilise `HybEnc` pour chiffrer le fichier et le nom de fichier en utilisant la clé publique du destinataire :
$$
nonceFilename = random[???]
$$
$$
nonceFile = random[???]
$$
$$
cipher1 = HybEnc(filename, nonceFilename, pub1Dest, priv1)
$$
$$
cipher2 = HybEnc(file, nonceFile, pub1Dest, priv1)
$$
- Le client signe le Message complet et la date autorisée d'ouverture du Message avec priv2

$$
signature = EdDSA_{priv2}(sender, receiver, timestamp, nonceFilename, filename, file)
$$
- Le client vérifie si la signature est correcte
- Le client envoie au serveur :
	- sender
	- MAC(sender)
	- receiver
	- timestamp
	- nonceFilename
	- cipherFilename
	- nonceFile
	- cipherFile
- Le serveur accepte de recevoir le message si le MAC est correct.

## Réception de Message
- Le client fait un login normal.
- Le client possède donc (priv1, pub1, priv2, pub2, key, key_communication)
- Le client fait une demande pour recevoir ses message en envoyant son username avec le MAC :
 $$
auth = MAC_{key\_communication}(username)
$$
- Le serveur vérifie si auth est juste, si c'est le cas, il renvoie tous les message au destinataire de la manière suivante:
	- Si le timestamp du message est dans le passé alors le serveur envoie :
$$
sender, receiver, timestamp, nonceFilename, cipherFilename, nonceFile, cipherFile, timePuzzle
$$
	- Si le timestamp est dans le futur, le serveur envoie tout mais met `nonceFile` à 0:
$$
sender, receiver, timestamp, nonceFilename, cipherFilename, 0, cipherFile, timePuzzle
$$
> Dans le cas ou le client à le droit de déchiffrer le message et que donc il est en possession du nonceFile, le serveur renvoie quand même un timePuzzle qui ne sert à rien. C'est pour simplifier l'implémentation.
> 
- Le client reçoit du serveur le message.
- Le client vérifie que la signature du Message est correcte
$$
signature' = EdDSA_{pubSender}(sender, receiver, timestamp, nonceFilename, filename, file)
$$
$$
signature = siganture'
$$
- Le client check si le nonceFile vaut 0:
	- si c'est le cas le client propose à l'utilisateur de déchiffrer localement en utilisant le time lock puzzle. Le client va donc ensuite commencer les calculs pour retrouver le nonceFile. Le nonceFile sera trouvé quand le time lock puzzle sera résolu, ce qui devrait prendre le même temps que d'attendre que le temps s'écoule et demander le nonceFile au serveur.
	- sinon le client écrit sur le disque le fichier chiffré sans pouvoir le déchiffrer. Il peut cependant déjà mettre le bon nom de fichier comme il a en sa possession filename et nonceFilename. Il peut également indiquer la date à laquelle le message pourra être déchiffré.
- Si le nonceFile ne vaut pas 0, le client déchiffre le Message m :
$$
m = HybDec(priv1, pubSender)
$$
## Types d'adversaires
- **Adversaires Actifs** :   
  - **Signatures Numériques** : Les messages sont signés avec les clés privées des utilisateurs, empêchant ainsi la répudiation et garantissant l'authenticité des messages. 
  - **Utilisation de TLS 1.3** : Toutes les communications entre le client et le serveur sont sécurisées avec TLS 1.3, protégeant les données en transit contre les interceptions et les modifications.  
- **Serveur Honnête mais Curieux** :   
  -  **Chiffrement de Bout en Bout** : Les messages sont chiffrés de bout en bout avec en utilisant du chiffrement hybride. Ce qui empêche le serveur d'en lire le contenu.
  - **Stockage Sécurisé des Clés** : Les clés privées des utilisateurs sont stockées chiffrées sur le serveur, empêchant l'accès non autorisé même en cas de compromission du serveur.
  - **Échange de clés authentifié** : L'utilisation de OPAQUE permet d'authentifier les utilisateurs, sans sortir le sel du serveur ce qui permet de ne pas avoir d'attaque à sel connu. Cela permet également de dériver une clé secrète côté client, et un clé symétrique partagée avec le serveur pour authentifié les requêtes suivantes provenant du client.