# Portail DSV Angers

Point d'entrée commun aux deux applis : **Plannings** (`planning-dsv-angers`) et **Gestion des véhicules** (`flotte-dsv-angers`). On s'y connecte une fois avec son code personnel, puis une tuile par appli l'ouvre sans retaper de code. La page Accès gère les personnes, leurs codes et leurs droits.

Les deux applis gardent leur dépôt, leur adresse et leur base Neon. Le portail a sa petite base à lui (personnes, codes, sessions).

**Ce dépôt est public : aucun code, aucune clé, aucune adresse de base ne doit y être écrit.** Tout se règle dans Vercel.

## Comment ça marche

- **Connexion** : code personnel seul (10 lettres ou chiffres minimum, majuscules et signes ignorés). Les codes sont gardés sous forme d'empreinte : personne ne peut les relire, même un administrateur.
- **Nouvelle personne** : un administrateur l'ajoute dans Accès ; le portail affiche un code provisoire une seule fois. À la première connexion, la personne choisit son propre code.
- **Code oublié** : « Réinitialiser le code » dans Accès donne un nouveau code provisoire.
- **Ouverture d'une appli** : le portail envoie la personne vers l'appli avec un jeton signé (`CLE_PORTAIL`), valable 1 minute et utilisable une seule fois. L'appli ouvre alors sa propre session de 12 h.
- **Droits** : Plannings (pas d'accès, modification), Véhicules (pas d'accès, consultation, modification), case Administrateur (page Accès, et rôle administrateur dans les applis). Chaque appli redemande au portail toutes les 5 minutes si la session est toujours ouverte et le droit toujours là : un accès retiré, une personne désactivée ou une déconnexion coupent l'appli en 5 minutes au plus. Si le portail ne répond pas, les applis déjà ouvertes continuent.
- **Code de secours** : `CODE_ADMIN` ouvre le portail en administrateur (premier lancement, ou code perdu).
- **Reprise du planning** : dans Accès, « Reprendre du planning » copie les personnes du planning avec leurs codes actuels (à faire sur un portail encore vide).

## Mise en ligne (Vercel)

1. Vercel > Add New > Project : importer le dépôt `portail-dsv-angers`, sans rien changer aux réglages de build.
2. Onglet Storage : créer une base Neon et la relier au projet (`DATABASE_URL` est ajoutée automatiquement).
3. Settings > Environment Variables (voir ci-dessous), puis Deployments > Redeploy.
4. Régler `PORTAIL_URL` et `CLE_PORTAIL` dans les deux applis (voir leur README), puis Redeploy de chacune.
5. Se connecter au portail avec `CODE_ADMIN`, page Accès : « Reprendre du planning », puis donner les droits Véhicules et ajouter les autres personnes.

## Réglages Vercel (Settings > Environment Variables)

- `DATABASE_URL` : ajoutée automatiquement quand on relie une base Neon.
- `CODE_ADMIN` : code de secours, 10 caractères minimum.
- `NOM_ADMIN` (facultatif) : nom affiché pour le code de secours, par exemple `Antoine`.
- `CLE_PORTAIL` : clé partagée, 32 caractères minimum, **la même valeur** dans le portail, le planning et la flotte. La changer coupe toutes les entrées par le portail.
- `PLANNING_URL` : adresse du planning, par exemple `https://planning-dsv-angers.vercel.app`.
- `FLOTTE_URL` : adresse de la flotte, par exemple `https://flotte-dsv-angers.vercel.app`.

`/api/health` indique si la base, la clé et les deux adresses sont réglées.

## Essayer en local

Avec une base Postgres locale : `DATABASE_URL=postgres://… CODE_ADMIN=un-code-de-test npm run dev`, puis ouvrir http://localhost:3000.
