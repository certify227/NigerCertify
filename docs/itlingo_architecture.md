# Architecture ITLingo

ITLingo est un socle d'application d'apprentissage informatique inspire de Duolingo :

- **Flutter** pour un client unique mobile et Windows desktop.
- **Django REST Framework** pour exposer les parcours, lecons, defis et progression.
- **SQLite en developpement**, remplacable par PostgreSQL en production.

## Flux MVP

1. L'application charge les parcours via `GET /api/tracks/`.
2. L'apprenant ouvre une lecon via `GET /api/lessons/<id>/`.
3. Chaque reponse est envoyee a `POST /api/challenges/<id>/submit/`.
4. Le backend renvoie correction, explication, bonne reponse et XP gagne.
5. Si l'utilisateur est authentifie, la progression est persistee.

## Evolutions recommandees

- Ajouter JWT ou OAuth pour connecter mobile et desktop au meme compte.
- Ajouter un back-office de creation de cours si l'admin Django devient insuffisant.
- Ajouter des ligues, objectifs quotidiens, coeurs et revision espacee.
- Passer a PostgreSQL et stocker les medias de cours dans un bucket objet.
- Ajouter des tests end-to-end Flutter quand le SDK est disponible en CI.
