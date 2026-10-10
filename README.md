# SW-P-08 — service Bobi.Tools

Serveur **SW-P-08** (Pro-Bel *General Remote Control Protocol*) pour
[Bobi.Tools](https://github.com/bob-integration/bobitools) : Bobi.Tools se présente au
contrôleur broadcast comme un **routeur nommé**, avec noms de sources, de destinations et
libellés UMD, par matrice et par niveau.

Un service n'apparaît pas au lanceur : il se règle dans **Réglages → Protocoles → SW-P-08**.

## Ce que fait le service

- **Écoute en TCP** : Bobi.Tools est le routeur, le contrôleur est client (16 clients au plus).
  Mode étendu par défaut (65 535 signaux, 256 niveaux).
- **Nomme un parc de passerelles IP** (profil IPG) : la matrice est l'étage de routage
  (entrées, sorties, affectation), le niveau est l'essence (vidéo, audio 1, audio 2, ANC). Les
  numéros sont ceux du service [Ember+](https://github.com/bob-integration/bobitools-service-emberplus).
  Ce volet suppose une couche IPG installée.
- **Grille VLAN** (matrice 10 par défaut, 0 l'éteint) : le plan de ports et de VLAN du parc
  vient de [Pilotage de switch](https://github.com/bob-integration/bobitools-plugin-switch_ports) ;
  un point de croisement change le VLAN d'un port. Le dernier plan connu est conservé sur
  disque.
- **Libellés réglables** : largeur 4, 8 ou 12 caractères, gabarits (`{short} {kind}{n}`…),
  libellé des positions inutilisées.
- **Banc d'essai** : une matrice 8×8 aux octets connus, et un aperçu hexadécimal commenté des
  trames construit sans ouvrir de socket.

## À savoir

- **Tant que le port vaut 0, rien n'écoute**, même service activé : aucun port n'est présumé.
- Les tables de noms sont **poussées** au contrôleur (réglable) : le contrôleur visé ne les
  demande jamais.
- La couche liaison est validée contre les trames de la spécification. Les **commandes de
  noms** ne figurent dans aucune spécification publique (elles suivent le module Companion
  `generic-swp08`) : l'aperçu hexadécimal sert à les confronter au banc.
- Le routage des signaux n'est **jamais** accepté par ce canal : il reste sur Ember+. Seuls
  l'affectation d'un matériel à un slot et la grille VLAN acceptent des écritures.

## Prérequis

- Aucun : le service tourne dans Bobi.Tools, sans dépendance Python supplémentaire.
- Un contrôleur broadcast parlant SW-P-08 en TCP.
- Pour la grille VLAN : le plugin
  [Pilotage de switch](https://github.com/bob-integration/bobitools-plugin-switch_ports).

## Installation

Dans Bobi.Tools : **Réglages → Outils → Catalogue**, bouton « Installer ». Ou, sur une machine
neuve, en une ligne :

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/bob-integration/bobitools/main/get.sh) --outils swp08
```

Un service se charge au démarrage : redémarrer Bobi.Tools après l'installation. Puis, dans
**Réglages → Protocoles → SW-P-08**, l'activer **et** choisir un port.

## Sécurité

- **SW-P-08 ne prévoit aucune authentification** : filtrer le port au niveau réseau.
- Restreindre les écritures par adresse : `swp08_write_allow` pour l'affectation,
  `swp08_vlan_write_allow` pour la grille VLAN (vide = reprend la première liste). Liste vide
  partout = aucune restriction.
- Pour soumettre un contrôleur aux règles de périmètre, le déclarer dans
  **Réglages → Protocoles → Contrôleurs**.

## In English

**SW-P-08 router server** for Bobi.Tools: it listens on TCP and presents itself to a broadcast
controller as a named router. Matrices are routing stages and levels are essences (video,
audio 1, audio 2, ANC) for an IP gateway fleet using the Ember+ numbering, plus a VLAN grid fed
by the `switch_ports` plugin. It includes an 8×8 test matrix and an annotated hex preview.
Nothing listens until a port is set. The protocol has no authentication: filter it at network
level and restrict writes by address.

## Licence

GPL-3.0-or-later — © 2026 BOBI SAS. Voir [LICENSE](LICENSE).
