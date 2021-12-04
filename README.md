# Node API RESTfull

*Interface de programmation pour applications Javascript*

![](https://i.imgur.com/wFj6sGt.png)

> &copy; [Julien Noyer](https://www.linkedin.com/in/julien-n-21219b28/) - All rights reserved for educational purposes only

<br>

## Présentation du projet

Une interface de programmation, plus communément appelée API, est une application constituée d’un ensemble de fonctions et de méthodes qui on pour but de gérer le transfert d’informations entre applications. Elle prend la forme d’un service web, c’est à dire qu’elle est disponible en ligne via le protocole HTTP. Dans la mesure ou le traitement de l’information est au centre du Web L’API est devenue central dans la plupart des projets Web, nous parlons donc aujourd’hui du principe de API-First Approach dans le développement de projet Web.

Ce principe qui consiste à commencer par structurer une API comme point de départ du développement d’un projet induit de respecter des normes afin de rendre nos API accessibles et structurées. C’est pourquoi ce document va prendre le parti de présenter une méthode de développement qui correspond aux critères des API REST qui représentent aujourd’hui la norme la plus utilisée.

<br>

## Définition du répertoire

L'objectif de ce répertoire est de mettre en place une structure de base pour une API RESTfull en NoeJS, le code présent dans ce répertoire doit permettre l'élaboration de système complexes de gestion de l'information. Pour atteindre cette objectif, le système développé dispose des fonctionnalités suivantes :

- Configuration du framework ExpressJS
- Connexion à une base de données MongoDB
- Inscription d'une identité
- Connexion d'une identité
- Déconnexion d'une identité
- Protection des routes pour identité connectée

Une documentation [Postman](https://learning.postman.com) a été créée pour cette API, vous pouvez y accéder avec le lien suivant : https://documenter.getpostman.com/view/1383513/UVJhCuj5

<br>

### Aller plus loin avec ce répertoire

Le code contenu dans ce répertoire représente certaines notions, aussi importantes soit-elles, présentent dans une API RESTfull, mais n'est pas un système qui peut être mis en production tel que. Si vous souhaitez utiliser ce répertoire pour l'un de vos projet, il vous faudra encore :

- Mettre en place un "router" dynamique
- Mettre en place un CRUD (https://github.com/DWS-paris/node-api-restfull)
- Mettre en place un serveur S3 de stockage (https://dwsapp.io/tuto/SJjk_SDVO)
- Déployer l'API RESTfull sur un VPS (https://dwsapp.io/tuto/HkLpPSPVd)

<br><br>

## Utilisation de ce répertoire

![](https://i.imgur.com/eAySYs0.png)

Avant toutes choses, comme pour tous les projets NodeJS, vous devez l'avoir installer sur votre machine. Pour cela, vous devez vous rendre sur le site officielle de NodeJS (https://nodejs.org/en/) pour installer la version qui correspond à votre système d'exploitation.

> Vous pouvez vérifier votre installation avec la commande `node -v`.

<br>

Une fois que votre machine est configurée vous devez installer les dépendances pour construire le dossier `node_modules` contenant les modules de l'application :

```bash
npm i
```

<br>

Cette API utilise des variables d'environnement, il s'agit d'une des bonnes pratiques de base à observer lorsque l'on travail sur des logiques serveurs : cacher certaines information. Pour ce faire, l'API utilise le module [Dotenv](https://www.npmjs.com/package/dotenv) qui charge un fichier nommée `.env` au changement de l'API. Vous devez donc créer ce fichier en vous basant sur le fichier `.env.dist` : 

```bash
# Serveur
PORT=<IP>
MONGO_URL=<MONGO-ORIGIN-FOLDER>

# CRYPTO
CRYPTO_KEY=<KEY>

# JWT
JWT_SECRET=<KEY>

# COOKIE
COOKIE_SECRET=<KEY>
COOKIE_NAME=<NAME>
```

<br>

Pour pouvoir définir l'URI d'origine de votre serveur de base de données [MongoDB](https://www.mongodb.com), vous devez au préalable l'avoir installer sur votre machine. Vous devez vous rendre sur le site officiel de [MongoDB](https://www.mongodb.com) pour séléectionner la version qui correspond à vos besoins et à votre système d'exploitation.

Une fois [MongoDB](https://www.mongodb.com) installé, vous aurez probablement besoin de modifier le script présent dans le fichier `package.json` selon votre configuration : 

```json
"scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "mongo": "sudo mongod --dbpath /MONGO_db",
    "start": "nodemon server.js"
},
```

> Ce script a été prévu pour une machine qui stocke les document dans un dossier `MONGO_db` à la racine de la machine.

<br>

Lorsque votre environnement de développement est prêt, vous devez dans un premier temps lancer votre serveur de base de données [MongoDB](https://www.mongodb.com) en tapant la commande suivante :

```bash
npm run mongo
```

<br>

Une fois le serveur de base de données actif, il ne vous reste plus qu'à lancer votre API avec la commande suivante :

```bash
npm run start
```

> Le script `start` utilise `nodemon` que vous devez au préalable installer en global sur votre machine.

<br>

### Learn at least one new thing every day 

- **Développer une API REST en NodeJS** https://dwsapp.io/tuto/HkLpPSPVd
- **Configurer un serveur NGINX** https://dwsapp.io/tuto/BJswWiONu
- **Minio Multi-Cloud Object Storage** https://dwsapp.io/tuto/SJjk_SDVO
- **Site officiel NodeJS** https://nodejs.org/en/