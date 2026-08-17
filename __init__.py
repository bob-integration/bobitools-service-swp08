# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Service SW-P-08 — Bobi.Tools se présente au pupitre comme un ROUTEUR nommé.

Raison d'être. La grille Ember+ n'émet que des numéros (EMBERPLUS-IPG.md §12.9.1) et le TSL
5.0, qui devait porter les noms, s'est révélé inapplicable ici : le récepteur visé n'expose pas
la notion d'écran et n'offre qu'un espace PLAT de 1024 canaux, alors qu'il faut nommer les
voies, les connecteurs des deux sens et les quatre essences — soit treize destinations réseau
distinctes. SW-P-08 a nativement les deux dimensions qui manquaient.

── La correspondance, et c'est tout le service ──────────────────────────────────────────
    MATRICE = l'étage de routage          NIVEAU = l'essence
      matrice « entrées » : sources = connecteurs d'entrée   destinations = voies
      matrice « sorties » : sources = voies                  destinations = connecteurs de sortie
      niveaux : 0 vidéo · 1 audio 1 · 2 audio 2 · 3 ANC

C'est exactement la structure des grilles Ember+ (1011/1012 vidéo, 1013/1014 audio, 1015/1016
ANC), transposée sans rien réinventer. Et surtout, sources et destinations sont deux espaces
SÉPARÉS dans chaque matrice : le numéro 101 peut donc désigner le connecteur d'entrée 1 en
source et la voie 1 en destination, comme du côté Ember+, sans le recouvrement qui condamnait
le TSL.

── Sens du flux ─────────────────────────────────────────────────────────────────────────
Nous ÉCOUTONS (Appendix 2 de la spec : le serveur TCP est du côté routeur, le contrôleur est
client, 16 clients simultanés au plus). Le pupitre demande, on répond. Aucune écriture vers du
matériel n'est acceptée aujourd'hui : ce service ne fait que NOMMER — le routage reste sur
Ember+, qui l'assure déjà et dont on ne veut pas deux sources de vérité.

⚠ **Tout est en base 0 sur le fil.** Matrice, niveau, source et destination : la spec l'écrit
noir sur blanc (« note all protocol data is based from zero ») avec un exemple où « Matrice 2,
Niveau 2, Destination 3 » s'encode `11 00 02 00`. Les réglages, eux, sont en base 1 comme ce
que lit l'exploitant — la conversion se fait ici et NULLE PART ailleurs. Même piège que le −1
d'Ember+, même remède : un seul endroit qui décale.

── Ce qui n'est pas vérifié ─────────────────────────────────────────────────────────────
La couche liaison est validée contre les trames de la spec (cf. `swp08.py`). Les COMMANDES DE
NOMS ne le sont pas : elles ne figurent dans aucune spec publique — l'Issue 4b s'arrête aux
« main commands » — et viennent du module Companion `generic-swp08`. Leur disposition exacte
est donc à confronter au banc, ce à quoi sert la prévisualisation hexadécimale commentée.
"""
import logging
import socket
import threading
import time

from app import settings, tools
from app.database import audit_log
from . import swp08 as proto

log = logging.getLogger(__name__)

SWP08_ACTOR = "Service SW-P-08"

MAX_CLIENTS = 16          # plafond de la spec (Appendix 2)
ACCEPT_TIMEOUT_S = 1.0
CLIENT_IDLE_S = 300

# ── Plan des niveaux — LE CONTRAT ────────────────────────────────────────────────────────
# Un niveau par couple (essence, direction), puis l'affectation. L'ordre EST le contrat : le
# changer renomme tout au pupitre, exactement comme renuméroter une racine Ember+.
#
# Pourquoi la DIRECTION mérite un niveau alors que l'essence n'y change rien. Le nom d'un
# connecteur ne dépend pas de l'essence qu'on y regarde — « PY1 SDI1 » est le même BNC en
# vidéo comme en ANC — donc les niveaux d'une même direction portent des libellés identiques.
# La direction, elle, change tout : en entrée une destination est une VOIE, en sortie c'est un
# CONNECTEUR, et les deux revendiquent le numéro 101. Sans niveau pour les séparer, l'un
# écrase l'autre.
#
# ⚠ Cela suppose que le contrôleur redemande les DESTINATIONS pour chaque niveau. Les sources
# portent un niveau sans ambiguïté ; pour les destinations, le champ existe en mode standard
# (4 bits) mais le mode étendu n'en a pas, et certaines implémentations l'ignorent. Si VSM ne
# demande les destinations qu'une fois, les niveaux de sortie rendront les mêmes que l'entrée
# et les connecteurs de sortie resteront anonymes — ce qui se verra dans le journal, où le
# niveau de chaque requête est tracé.
LEVEL_PLAN = (
    (1, "in", "video"), (2, "out", "video"),
    (3, "in", "audio1"), (4, "out", "audio1"),
    (5, "in", "audio2"), (6, "out", "audio2"),
    (7, "in", "anc"), (8, "out", "anc"),
    (9, "assign", None),
)

# ⚠ CONSTATÉ SUR LE PUPITRE RÉEL (2026-07-30) : ce que VSM appelle un « layer » est la
# MATRICE de SW-P-08, pas le niveau. Configurer le layer 9 nous a fait recevoir l'octet 0x80 —
# quartet haut à 8, donc matrice 9 en base 1 — le quartet de niveau restant à zéro. La
# répartition ci-dessus s'indexe donc sur la MATRICE, et le plan tient dans les 16 valeurs du
# quartet, ce qui recoupe le « jusqu'à 16 layers par connexion » de leur documentation.
# Le niveau reste disponible pour un usage ultérieur ; aujourd'hui il ne porte rien.
ESSENCE_LABELS = {"video": "vidéo", "audio1": "audio 1", "audio2": "audio 2",
                  "anc": "ANC", None: "—"}
STAGE_LABELS = {"in": "entrées", "out": "sorties", "assign": "affectation",
                "test": "banc d'essai"}

# Suffixe d'essence ajouté au libellé. RIEN pour la vidéo : c'est l'essence par défaut, celle
# qu'on regarde neuf fois sur dix, et l'alourdir gaspillerait des caractères sur les douze que
# le protocole accorde. Les autres se signalent, sinon rien ne distingue le layer où on se
# trouve — le nom d'un signal, lui, ne dépend pas de l'essence qu'on y regarde.
#
# Pourquoi « AU1 » et non « A1 » : les SNP et les Neuron nomment leurs voies « A1 »… « D8 » ou
# « H4 », donc un suffixe « A1 » donnerait « SNP1 A1 A1 » — et « SNP1 A2 A2 » pour le canal A2
# en audio 2, franchement trompeur. Et pas « Audio1 » non plus : six caractères sur douze
# mangent le nom du canal, si bien que les 32 voies d'un SNP se liraient toutes « SNP1 Audio1 ».
# Trois caractères sont le point d'équilibre — mesuré, pas supposé.
ESSENCE_SUFFIX = {"video": "", "audio1": "AU1", "audio2": "AU2", "anc": "ANC", None: ""}


def _suffixe(labels, essence, largeur):
    """Ajoute le suffixe d'essence à un jeu de libellés, en tenant dans la largeur imposée.
    On tronque le NOM et jamais le suffixe : perdre le suffixe rendrait deux layers
    indiscernables, alors qu'un nom raccourci reste lisible."""
    suf = ESSENCE_SUFFIX.get(essence) or ""
    if not suf:
        return labels
    garde = largeur - len(suf) - 1
    # Les PSEUDO-signaux (bloc bas, 1..99 : « Disconnect », « Mire ») ne portent pas d'essence
    # — ce sont des gestes, pas des flux. Les suffixer les tronquerait pour rien : le protocole
    # ne laisse que douze caractères, et « Disconnec A1 » ne dit rien de plus que « Disconnect ».
    return {n: (v if (n < 100 or not v)
                else "%s %s" % (str(v)[:garde].rstrip(), suf))
            for n, v in labels.items()}

# niveau AFFICHÉ (base 1) → étage
_STAGE_OF_LEVEL = {lvl: stage for lvl, stage, _ in LEVEL_PLAN}
_ESSENCE_OF_LEVEL = {lvl: ess for lvl, _st, ess in LEVEL_PLAN}

# Layer → grille canonique du plan IPG, et décalage d'essence. C'est `ipg_io.apply_connect` qui
# applique réellement le crosspoint : il connaît les numéros émis, les essences, et sait refuser
# ce que le matériel refuse. On ne retraduit rien ici — une seconde traduction serait une
# seconde vérité, et c'est tout ce que ce projet passe son temps à supprimer.
#
# L'audio 2 vit au-dessus de tous les numéros de base (§12.10) : les grilles audio portent les
# deux essences, séparées par ce décalage. Le layer, lui, les distingue déjà — on rajoute donc
# le décalage AVANT d'appeler, pour parler la langue des grilles.
_CANON_OF_LEVEL = {
    1: ("video_in", 0), 2: ("video_out", 0),
    3: ("audio_in", 0), 4: ("audio_out", 0),
    5: ("audio_in", "audio2"), 6: ("audio_out", "audio2"),
    7: ("anc_in", 0), 8: ("anc_out", 0),
}
DEFAULT_STAGE = "in"        # un niveau hors plan retombe sur l'étage d'entrée

_lock = threading.Lock()
_sock = None
_thread = None
_stop = threading.Event()
_clients = {}
_status = {"running": False, "port": 0, "clients": 0, "last_error": None,
           "requests": 0, "labels_sent": 0, "started_at": None}


# ═════════════════════════════════════════════════════════════════════
# Réglages
# ═════════════════════════════════════════════════════════════════════

def _int_setting(key, default, lo, hi):
    try:
        v = int(settings.get(key) or default)
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def port():
    """Port d'écoute, ou 0 s'il n'est pas configuré. AUCUN défaut : la spec dit que le port se
    configure par installation, il n'y a pas de valeur universelle à présumer."""
    return _int_setting("swp08_port", 0, 0, 65535)


def label_chars():
    """4, 8 ou 12. Toute autre valeur est ramenée à la plus proche admise — le protocole n'en
    connaît que trois, et une quatrième ne se négocie pas."""
    want = _int_setting("swp08_label_chars", 12, 1, 64)
    return min(proto.CHAR_LENGTHS, key=lambda c: (abs(c - want), -c))


def sdi_per_slot():
    """Connecteurs SDI ÉMIS par slot dans les grilles. Borne d'ÉMISSION, pas du plan : le plan
    en réserve 50 (§12.2), mais les émettre tous pour seize slots ferait 800 libellés par
    grille alors que la plus grosse machine du parc en porte 40. L'agrandir est sûr (on ajoute
    en fin) ; le réduire fait disparaître des libellés déjà câblés au pupitre."""
    return _int_setting("swp08_sdi_per_slot", 40, 1, 50)


def ip_per_slot():
    """Idem pour les Rx/Tx IP (le plan en réserve 49)."""
    return _int_setting("swp08_ip_per_slot", 32, 1, 49)


def matrices():
    """{« étage »: numéro de matrice AFFICHÉ (base 1)}."""
    return {"in": _int_setting("swp08_matrix_in", 1, 1, 256),
            "out": _int_setting("swp08_matrix_out", 2, 1, 256)}


def extended():
    """Jeu de commandes étendu : 65 535 signaux et 256 niveaux, contre 1 024 et 16 en
    standard. Notre plan monte à 1699 pour 16 slots, donc l'étendu n'est pas un confort.

    `settings.get` ne prend PAS de défaut en argument : il le tire du manifeste du service
    (`_service_defaults`), où `swp08_extended` vaut true."""
    return bool(settings.get("swp08_extended"))


def _fmt(key, default):
    v = settings.get(key)
    return str(v) if isinstance(v, str) and v.strip() else default


def _short_names():
    raw = settings.get("swp08_short_names")
    return raw if isinstance(raw, dict) else {}


# ═════════════════════════════════════════════════════════════════════
# Le parc, vu de la couche IPG
# ═════════════════════════════════════════════════════════════════════

def _ipg():
    """(module ipg_io, erreur). Dépendance à sens unique et assumée, comme pour le TSL : ce
    service NOMME ce que la couche IPG expose, et les numéros viennent d'elle seule — les
    recalculer ici serait la garantie d'une divergence silencieuse."""
    try:
        from services.emberplus import ipg_io
    except Exception as e:
        return None, "services.emberplus.ipg_io illisible : %s" % e
    return ipg_io, None


def _auto_short(label):
    """Nom court de repli quand aucun n'est saisi : initiales des mots + chiffres terminaux.
    « Pélicase YB #1 » → « PYB1 ». Approximatif par nature — c'est un pis-aller lisible en
    attendant que l'exploitant saisisse le sien, pas une politique de nommage."""
    txt = str(label or "").strip()
    if not txt:
        return "?"
    mots = [m for m in txt.replace("#", " ").split() if m]
    ini = "".join(m[0] for m in mots if m[0].isalpha()).upper()
    chiffres = "".join(c for c in txt if c.isdigit())
    return ((ini or txt[:3].upper()) + chiffres)[:8] or "?"


def _short(key, label, declare=None):
    """Nom court d'un matériel, par ordre d'autorité : celui que déclare la COUCHE IPG (saisi
    par l'exploitant dans l'outil), puis une surcharge propre à ce service, puis le repli
    automatique. La couche IPG prime parce que le nom appartient au matériel, pas au
    protocole — le TSL doit pouvoir lire le même."""
    if isinstance(declare, str) and declare.strip():
        return declare.strip()
    val = _short_names().get(key)
    return str(val).strip() if isinstance(val, str) and str(val).strip() else _auto_short(label)


def _format(tmpl, **kw):
    try:
        return tmpl.format(**kw)
    except (KeyError, IndexError, ValueError):
        return kw.get("short", "")


MODEL_TTL_S = 20
_model_lock = threading.Lock()
_model = {"tables": None, "error": None, "ts": 0.0}
_contributor = None          # type d'outil portant la couche IPG (déduit, jamais codé en dur)

# ── Matrice de TEST ──────────────────────────────────────────────────────────────────────
# Un banc d'essai minuscule dont on connaît chaque octet : 8 sources, 8 destinations,
# numérotées 1 à 8, des libellés évidents, et des croisements qui TIENNENT en mémoire.
#
# Sa raison d'être : séparer « le protocole est-il juste ? » de « notre modèle est-il juste ? ».
# Le parc réel numérote ses signaux à partir de 101 (§12.2) et en compte 80 par étage ; si le
# pupitre n'affiche rien, on ne sait pas si c'est le format des trames ou une plage hors de ce
# qu'il attend. Ici il n'y a plus qu'une variable.
TEST_SIZE = 8
_test_tally = {n: n for n in range(1, TEST_SIZE + 1)}   # au départ, chaque dest sur sa source

# Sources IMPOSSIBLES du banc d'essai. Le banc ne sert plus seulement à prouver que la boucle du
# protocole tourne : il sert à éprouver le REFUS. Le matériel réel ne sait pas refuser sur
# commande — il faut lui demander quelque chose de précisément impossible, ce qui dépend de son
# câblage du moment et change sous nos pieds. Ici, la moitié haute des sources refuse toujours,
# sans matériel, sans attente et sans effet de bord.
TEST_REFUS_MIN = 5

# Comment on refuse. Le protocole n'ayant pas de message « refusé » (§3.2.2 : le routeur fait la
# route et répond CONNECTED), il faut détourner ce qu'il a. Réglable pour qu'on puisse comparer
# les quatre au banc en quelques secondes, plutôt que de raisonner sur la spécification :
#   tally — CONNECTED sur la source demandée, puis TALLY sur la réelle (cf. `_answer_xpt`)
#   nak   — on REFUSE la trame elle-même (§7.2.2). Suppose de n'acquitter qu'après avoir
#           tranché, alors qu'on acquitte d'ordinaire d'emblée : le pupitre retransmet cinq
#           fois en l'absence d'acquittement, donc la décision doit être rapide.
#   oor   — TALLY portant la source 1023, « reserved to indicate destination out of range »
#           (§3.2.3). Seule valeur d'erreur de toute la famille crosspoint.
#   muet  — on ne répond rien. Témoin, pour distinguer ce qui vient de nous de ce qui vient
#           du pupitre.
REFUS_MODES = ("tally", "nak", "oor", "muet")
OOR_SOURCE = 1023               # base 0 sur le fil, comme tout le reste du protocole


def _refus_mode():
    v = str(settings.get("swp08_refus_mode") or "").strip().lower()
    return v if v in REFUS_MODES else "tally"


def test_matrix():
    """Numéro de matrice servant le banc d'essai, ou 0 si le mode test est éteint."""
    if not bool(settings.get("swp08_test")):
        return 0
    return _int_setting("swp08_test_matrix", 1, 1, 16)


def model(force=False):
    """Modèle en CACHE. Sa construction interroge tout le parc — mesuré à 7 s sur cette
    installation, le SNP répondant en 4 à 9 s — ce qui est inacceptable dans la boucle de
    réponse : le pupitre acquitte en une seconde et retransmet cinq fois. Un premier essai a
    d'ailleurs fini en « broken pipe », le client ayant raccroché avant la réponse.

    Deux règles qui en découlent :
      • une reconstruction en cours ne bloque personne — on sert la copie PÉRIMÉE plutôt que
        de faire attendre, un nom d'il y a vingt secondes valant mieux qu'un silence ;
      • le cache est préchauffé au démarrage, pour que le premier client n'essuie pas les
        plâtres."""
    with _model_lock:
        frais = (_model["tables"] is not None
                 and (time.monotonic() - _model["ts"]) < MODEL_TTL_S)
        if frais and not force:
            return _model["tables"], _model["error"]
        occupe = _model.get("building")
        if occupe and _model["tables"] is not None:
            return _model["tables"], _model["error"]     # périmé mais servable
        _model["building"] = True
    try:
        tables, err = _build_model()
    except Exception as e:                               # jamais lever dans une boucle réseau
        tables, err = None, "construction du modèle échouée : %s" % e
    with _model_lock:
        _model["building"] = False
        if tables is not None:
            _model.update(tables=tables, error=err, ts=time.monotonic())
        else:
            _model["error"] = err
            if _model["tables"] is not None:
                # On sert le dernier bon modèle plutôt que rien — mais on REND l'erreur, et on
                # la journalise. La masquer laissait croire à un modèle frais alors qu'il datait
                # d'avant l'échec : c'est comme ça qu'un parc vidé a semblé encore peuplé, et
                # le diagnostic est parti dans le décor pendant un moment.
                log.warning("swp08: modèle périmé servi — %s", err)
                return _model["tables"], err
        return _model["tables"] or {}, _model["error"]


def _build_model():
    """Le parc traduit en termes SW-P-08, prêt à répondre :

        {(étage, "source"|"dest"): {numéro affiché: libellé}}

    Les numéros sont ceux du plan Ember+ (§12.2), repris tels quels de `ipg_io` — c'est la
    propriété qu'on cherchait depuis le début : un même signal porte le même nombre dans les
    deux protocoles. Les niveaux ne changent PAS les numéros (une essence n'est pas un autre
    signal, c'est une couche du même), donc un seul jeu de libellés sert tous les niveaux.
    """
    global _contributor
    ipg_io, err = _ipg()
    if err:
        return {}, err
    try:
        state = ipg_io.collect()
        # Type d'outil qui porte la couche IPG, retenu pour lui renvoyer les affectations.
        # On ne le code pas en dur : ce service n'a pas à connaître le nom de l'outil qui
        # l'alimente, juste à savoir à qui réexpédier une écriture.
        # ⚠ NE PAS le déduire des matériels affectés : l'agrégateur ne publie que ce qui est
        # posé sur un slot, donc vider tous les slots effacerait la dernière trace de son
        # existence et plus rien ne pourrait être réaffecté — un aller sans retour, constaté
        # au banc le 2026-07-30. On lit le REGISTRE DES OUTILS, qui ne dépend d'aucun état.
        _contributor = next(iter(ipg_io.io_types()), None) or next(
            (d.get("type") for d in (state.get("devices") or {}).values() if d.get("type")),
            None)
    except Exception as e:
        return {}, "collecte du parc échouée : %s" % e

    sig_fmt = _fmt("swp08_signal_format", "{short} {kind}{n}")
    lane_fmt = _fmt("swp08_lane_format", "{short} V{lane}")
    slot_fmt = _fmt("swp08_slot_format", "IPG{slot} - {n}")
    vide = _fmt("swp08_unused_label", ".")
    nsdi, nip = sdi_per_slot(), ip_per_slot()
    nslots, nlanes = ipg_io.num_slots(), ipg_io.lanes_per_slot()
    out = {("in", "source"): {}, ("in", "dest"): {},
           ("out", "source"): {}, ("out", "dest"): {},
           ("assign", "source"): {}, ("assign", "dest"): {}}
    numbers = state.get("numbers") or {}

    # ── Grilles de signaux : PLEINES, comme celles d'Ember+ (§12.7) ───────────────────────
    # Toutes les positions de tous les slots portent un libellé, qu'un matériel soit posé ou
    # non. Trois cas, dans cet ordre :
    #   • position servie par un matériel affecté  → son vrai nom  (« SNP1 SDI5 »)
    #   • slot occupé, mais ce matériel n'a pas cette position → « . » (elle n'existe pas)
    #   • slot vide → nom POSITIONNEL (« IPG3 - 5 »), pour que le pupitre se câble d'avance
    # Sans ça, une position qui disparaît garde son ancien nom au pupitre, et une grille
    # à moitié nommée se lit comme une panne.
    for slot in range(1, nslots + 1):
        occupe = bool((state.get("by_slot") or {}).get(slot))

        def defaut(num, _slot=slot, _occupe=occupe):
            # Le « y » du gabarit est le numéro LOCAL du plan (§12.2) : 1..50 pour les SDI,
            # 51..99 pour les Rx/Tx IP. Reprendre l'index de la famille ferait porter le même
            # libellé au SDI 1 et au Rx IP 1 — ils sont pourtant deux signaux distincts.
            if _occupe:
                return vide
            local = num - ipg_io.SLOT_BLOCK * _slot
            return _format(slot_fmt, slot=_slot, n=local, short="", kind="",
                           lane=local, index=num, label="")

        for kind, count in (("sdi", nsdi), ("ip", nip)):
            for i in range(1, count + 1):
                num = ipg_io.phys_signal(slot, kind, i)
                out[("in", "source")][num] = defaut(num)
                out[("out", "dest")][num] = defaut(num)
        for lane in range(1, nlanes + 1):
            num = ipg_io.lane_signal(slot, lane)
            out[("in", "dest")][num] = defaut(num)
            out[("out", "source")][num] = defaut(num)
    for slot, key in sorted((state.get("by_slot") or {}).items()):
        dev = (state.get("devices") or {}).get(key) or {}
        court = _short(key, dev.get("label"), dev.get("short"))
        n = numbers.get(key)
        if n:
            # Le tally de l'affectation : le slot EST la destination, le matériel qui l'occupe
            # EST la source. Sans lui, un dump sur ce layer rend zéro croisement alors que
            # l'information est la plus simple du service — c'est ce qui manquait au premier
            # essai réel du 2026-07-30.
            out.setdefault(("assign", "tally"), {})[slot] = ipg_io.DEV_SRC_OFFSET + n
        # Connecteurs : sources de l'étage d'entrée, destinations de l'étage de sortie.
        for sens, etage, role in (("inputs", "in", "source"), ("outputs", "out", "dest")):
            for s in dev.get(sens) or []:
                num = ipg_io.phys_signal(slot, s["kind"], s["index"])
                out[(etage, role)][num] = _format(
                    sig_fmt, short=court, slot=slot, kind=s["kind"].upper(),
                    n=s["index"], index=num, label=s.get("label") or "", lane=0)
        # Voies : destinations de l'étage d'entrée, sources de l'étage de sortie.
        for lane in sorted(dev.get("lanes") or {}):
            num = ipg_io.lane_signal(slot, lane)
            # `{name}` = la désignation constructeur publiée par le matériel (« A1 » sur un
            # SNP ou un Neuron). Repli sur « V<voie> » pour les familles qui n'en ont pas :
            # un CDE ou un Newt ne nomment pas leurs voies, et il faut bien afficher quelque
            # chose dans les 12 caractères du protocole.
            nom = (dev.get("lanes") or {}).get(lane, {}).get("name") or ""
            lbl = _format(lane_fmt, short=court, slot=slot, lane=lane, name=nom or "V%d" % lane,
                          index=num, kind="V", n=lane, label="")
            out[("in", "dest")][num] = lbl
            out[("out", "source")][num] = lbl
            # ── Tally : QUI alimente cette voie ────────────────────────────────
            # L'état vient du matériel via `ember/io` — on ne l'invente pas. Une voie sans
            # source (« Désactivé ») reste absente du tally plutôt que d'être routée sur un
            # signal 0 qui existerait : le pupitre doit voir un point de croisement vide,
            # pas un faux.
            blk = ((dev["lanes"][lane].get("in") or {}).get(ipg_io.ESSENCE_VIDEO) or {})
            src = blk.get("src")
            if isinstance(src, dict) and src.get("kind") in ("sdi", "ip"):
                try:
                    out.setdefault(("in", "tally"), {})[num] = ipg_io.phys_signal(
                        slot, src["kind"], int(src["index"]))
                except (TypeError, ValueError):
                    pass
            # ── Étage de SORTIE : quelle voie alimente quel connecteur ──────────────────
            # Le sens s'inverse : ici la voie est la SOURCE et le connecteur la destination.
            # Sur la plupart des familles ces points sont épinglés (le programme d'un SNP
            # alimente en permanence son BNC et son Tx), mais épinglé ne veut pas dire absent :
            # sans ce tally, les quatre layers de sortie restaient vides au pupitre.
            oblk = ((dev["lanes"][lane].get("out") or {}).get(ipg_io.ESSENCE_VIDEO) or {})
            for dst in (oblk.get("dst") or []):
                if not isinstance(dst, dict) or dst.get("kind") not in ("sdi", "ip"):
                    continue
                try:
                    out.setdefault(("out", "tally"), {})[
                        ipg_io.phys_signal(slot, dst["kind"], int(dst["index"]))] = num
                except (TypeError, ValueError):
                    pass
    # ── Grille d'affectation : PLEINE, comme celle d'Ember+ (§12.7) ───────────────────────
    # Tous les slots émis figurent en destinations, occupés ou non, et TOUS les matériels
    # connus en sources, posés ou non. N'y mettre que l'affecté avait deux conséquences que le
    # banc a révélées : un slot vidé perdait son libellé, et le matériel qu'on venait d'en
    # retirer disparaissait des sources — donc impossible de le reposer. La grille pleine rend
    # aussi le pupitre configurable avant que le parc existe.
    for slot in range(1, ipg_io.num_slots() + 1):
        occupant = (state.get("by_slot") or {}).get(slot)
        court = None
        if occupant:
            dev = (state.get("devices") or {}).get(occupant) or {}
            court = _short(occupant, dev.get("label"), dev.get("short"))
        out[("assign", "dest")][slot] = ("Slot %d %s" % (slot, court)) if court \
            else "Slot %d" % slot
    for key, dev in sorted((state.get("devices") or {}).items()):
        n = numbers.get(key)
        if n:
            out[("assign", "source")][ipg_io.DEV_SRC_OFFSET + n] = _short(
                key, dev.get("label"), dev.get("short"))

    # ── Pseudo-sources : le bas de la plage (1..99), sans slot ────────────────────────────
    # Elles ne désignent aucun matériel mais elles sont COMMUTABLES, et c'est par elles qu'on
    # déconnecte. Sans libellé, le pupitre affiche un numéro nu là où l'opérateur cherche
    # « Disconnect » — et c'est justement la source qu'on lui envoie à chaque déconnexion.
    # Mêmes numéros que la grille Ember+, pour que les deux protocoles se lisent pareil.
    for etage in ("in", "out", "assign"):
        out.setdefault((etage, "source"), {})[ipg_io.PSEUDO_NONE] = "Disconnect"
    # La mire n'existe que sur l'étage d'entrée : c'est une source, jamais une sortie.
    out[("in", "source")][ipg_io.PSEUDO_PATTERN] = "Mire"
    out.setdefault(("in", "tally"), {})
    out.setdefault(("assign", "tally"), {})
    # Banc d'essai : indépendant du parc, donc toujours présent et toujours identique.
    # Les libellés DISENT lesquelles refusent : au pupitre on ne voit que des numéros, et un
    # essai de refus qu'on croit avoir lancé sur une source acceptante ne prouve rien.
    out[("test", "source")] = {n: "SRC %d %s" % (n, "KO" if n >= TEST_REFUS_MIN else "OK")
                               for n in range(1, TEST_SIZE + 1)}
    out[("test", "dest")] = {n: "DST %d" % n for n in range(1, TEST_SIZE + 1)}
    # Table UMD PROPRE au banc. En exploitation, une demande de libellés UMD est servie avec la
    # table des sources (cf. `responses_for`) : c'est un repli utile, mais il rend l'UMD
    # indiscernable du nom de source — donc intestable. Ici elle existe pour elle-même.
    out[("test", "umd")] = {n: "UMD %d" % n for n in range(1, TEST_SIZE + 1)}
    out[("test", "tally")] = dict(_test_tally)
    return out, None


# ═════════════════════════════════════════════════════════════════════
# Réponse à une demande de noms
# ═════════════════════════════════════════════════════════════════════

def _stage_of(matrix_displayed, level_displayed=1):
    """Étage servi par une requête. C'est la MATRICE qui porte la répartition — le « layer »
    de VSM, constaté sur le pupitre réel (cf. LEVEL_PLAN). Le niveau est accepté en second
    recours pour un contrôleur qui, lui, ferait varier ce champ-là : ça ne coûte rien et ça
    évite de retomber en panne devant une implémentation différente.

    Une valeur hors plan retombe sur l'étage d'entrée plutôt que de ne rien rendre : un
    contrôleur qui explore ne doit pas conclure au silence."""
    tm = test_matrix()
    if tm and matrix_displayed == tm:
        return "test"          # le banc d'essai prime : c'est le but, isoler le protocole
    st = _STAGE_OF_LEVEL.get(matrix_displayed)
    if st is None and level_displayed != 1:
        st = _STAGE_OF_LEVEL.get(level_displayed)
    return st or DEFAULT_STAGE


# Têtes de libellé du banc, par canal et par largeur : court (4), moyen (8), long (12).
_TEST_CANAL = {"dest": ("D", "DST", "DEST"),
               "source": ("S", "SRC", "SRCE"),
               "umd": ("U", "UMD", "UMDL")}


TEST_LABEL_LEVELS = 16     # VSM annonce 16 « Source Label » et 16 « Target Label » : on les remplit tous


def test_level():
    """Niveau UNIQUE sur lequel pousser les libellés du banc, ou -1 pour les seize.

    C'est l'essai qui DISCRIMINE. Pousser les seize niveaux ne dit rien : le contrôleur affiche
    le dernier arrivé, qu'il range par niveau ou qu'il écrase. Pousser un SEUL niveau, et un
    seul qui ne soit pas le 0, sépare les deux hypothèses sans ambiguïté :
      • rien ne s'affiche  → le niveau est honoré en réception, et seul le 0 est cartographié ;
      • « L05 » s'affiche  → le champ niveau est ignoré en réception, le dernier écrit gagne.
    Une mesure vaut mieux que deux lectures d'une documentation qui, elle, parle de ce que le
    contrôleur ÉMET (« is NOT sent anymore »), pas de ce qu'il ingère."""
    return _int_setting("swp08_test_level", -1, -1, TEST_LABEL_LEVELS - 1)


def _test_labels(labels, req):
    """Libellés du banc qui DISENT leur propre origine.

    « DEST12X 3 » se lit : table des DESTINATIONS, demandée en 12 caractères, jeu de commandes
    ÉTENDU, signal 3. L'écran du contrôleur répond alors tout seul aux deux questions qu'on ne
    peut pas trancher depuis le serveur — QUELLE table il affiche, et à QUELLE largeur il la
    demande. Sans ça, trois tables qui renvoient la même chaîne sont indiscernables une fois
    affichées, et l'on croit lire l'UMD alors qu'on lit les sources.

    C'est aussi la seule façon d'éprouver la piste « plusieurs niveaux de libellés » : si le
    pupitre demande successivement 4, 8 et 12, il montrera trois chaînes différentes."""
    kind = req["kind"] if req["kind"] in _TEST_CANAL else "source"
    w = req["char_length"]
    lvl = int(req.get("level") or 0) + 1        # base 1, comme au menu du contrôleur
    court, moyen, long_ = _TEST_CANAL[kind]
    if w <= 4:
        motif = "%s%d%%d" % (court, lvl)
    elif w <= 8:
        motif = "%sL%02d %%d" % (moyen, lvl)
    else:
        motif = "%s L%02d %%d" % (long_, lvl)
    return {n: (motif % n)[:w] for n in labels}


def responses_for(req, tables=None):
    """Liste de trames prêtes à partir, répondant à une demande décodée par `proto`.

    Une matrice inconnue rend une liste VIDE plutôt qu'une erreur : le pupitre interroge
    souvent tout ce qu'il sait faire, et répondre « je ne connais pas cette matrice » par un
    NAK ferait passer une exploration normale pour une panne."""
    if tables is None:
        tables, err = model()
        if err:
            return [], err
    etage = _stage_of(req["matrix"] + 1, req["level"] + 1)   # le fil est en base 0 (§10.3)
    # Les libellés UMD sont une table À PART dans le protocole (0x68), pas une vue des noms de
    # sources. On la sert quand elle existe, et on retombe sur les sources sinon — le repli
    # d'origine, qu'on garde pour ne rien changer au parc IPG.
    role = req["kind"] if req["kind"] in ("dest", "umd") else "source"
    table = tables.get((etage, role))
    if table is None and role == "umd":
        table = tables.get((etage, "source"))
    labels = _suffixe(table or {},
                      _ESSENCE_OF_LEVEL.get(req["matrix"] + 1), label_chars())
    if etage == "test":
        labels = _test_labels(labels, req)
    if not labels:
        return [], None
    data_list = proto.name_responses(
        req["kind"], labels, matrix=req["matrix"], level=req["level"],
        char_length=req["char_length"], extended=req["extended"], first=1)
    return [proto.pack(d) for d in data_list], None


# ═════════════════════════════════════════════════════════════════════
# Serveur TCP
# ═════════════════════════════════════════════════════════════════════

_received = {}          # (matrice, niveau, type) -> {numéro: libellé} poussés par le pupitre
_received_lock = threading.Lock()


def received_names():
    """Ce que le CONTRÔLEUR nous a poussé comme libellés. Purement documentaire aujourd'hui :
    on l'expose pour pouvoir comparer son plan de nommage au nôtre."""
    with _received_lock:
        return {"%d/%d/%s" % k: dict(v) for k, v in sorted(_received.items())}


def _absorb_names(addr, payload):
    """Absorbe une réponse de noms VENUE du contrôleur. Rend True si c'en était une.

    On ne les avait pas prévues — le protocole veut que le routeur nomme et que le pupitre
    lise. Celui-ci fait l'inverse : il a poussé 320 trames de libellés sans jamais rien
    demander. Les jeter serait perdre la seule information qu'il consent à donner sur son
    propre plan de nommage."""
    r = proto.decode_name_response(payload)
    if not r:
        return False
    cle = (r["matrix"] + 1, r["level"] + 1, r["kind"])
    with _received_lock:
        cur = _received.setdefault(cle, {})
        neuf = {n: l for n, l in r["labels"].items() if l}
        premier = not cur
        cur.update(neuf)
        total = len(cur)
    if premier:
        log.info("swp08: %s POUSSE ses libellés — matrice %d niveau %d, %s (%d à ce stade)",
                 addr, cle[0], cle[1], r["kind"], total)
    return True


_published = {}         # (layer, type) -> numéros déjà annoncés, pour savoir quoi EFFACER


def push_names(conn, tables=None, matrices_wanted=None, clear_stale=False):
    """Envoie NOS libellés au contrôleur SANS qu'il les ait demandés.

    Le protocole prévoit que le routeur soit interrogé (`100`/`102`) et réponde (`106`/`107`).
    Le pupitre visé ne demande jamais — mais il POUSSE les siens de la même façon, et sa table
    déclare `106` et `107` en « inbound », donc il sait les recevoir. On fait donc comme lui :
    on pousse. C'est le seul chemin qui garde le nommage du parc chez nous, et il ne coûte
    qu'un envoi de plus à la connexion.

    Renvoie le nombre de trames émises."""
    if tables is None:
        tables, err = model()
        if err:
            return 0
    n = 0
    # Le banc n'est PAS dans LEVEL_PLAN : ses libellés n'étaient donc jamais poussés, et comme
    # ce pupitre ne demande jamais rien (cf. ci-dessus), le banc était injoignable pour tout ce
    # qui touche au nommage. On l'ajoute à la tournée quand il est allumé — c'est la seule façon
    # de lui faire afficher quoi que ce soit.
    tournee = list(LEVEL_PLAN)
    if test_matrix():
        tournee = tournee + [(test_matrix(), "test", None)]
    for layer, _stage, _ess in tournee:
        if matrices_wanted and layer not in matrices_wanted:
            continue
        etage = _stage_of(layer)
        # L'UMD n'est poussé que là où une table lui est propre — aujourd'hui le banc. Le pousser
        # ailleurs enverrait les noms de sources en double sous un troisième code, ce qui
        # brouillerait justement la mesure qu'on cherche à faire.
        canaux = (("source", "source"), ("dest", "dest"))
        if tables.get((etage, "umd")):
            canaux = canaux + (("umd", "umd"),)
        for kind, role in canaux:
            labels = _suffixe(dict(tables.get((etage, role)) or {}),
                              _ESSENCE_OF_LEVEL.get(layer), label_chars())
            cle = (layer, kind)
            if clear_stale:
                # Un matériel qui rétrécit ou s'en va laisse des numéros ORPHELINS : le SNP et
                # ses 32 voies remplacé par un CDE et ses 4, ce sont les voies 5 à 32 qui
                # n'existent plus. Ne rien envoyer pour elles laisse le pupitre afficher
                # l'ancien nom indéfiniment — constaté au banc : « SNP1 V5 » restait sur le 305
                # après le déménagement. On les efface donc explicitement, par un libellé vide.
                for orphelin in (_published.get(cle, set()) - set(labels)):
                    labels[orphelin] = ""
            if not labels:
                continue
            # Le NIVEAU des commandes de noms est un second index de libellé, distinct du
            # routage : le contrôleur annonce 16 « Source Label » et 16 « Target Label », soit
            # exactement les 16 valeurs du quartet. On n'a jamais poussé que le niveau 1 —
            # `level=0` en dur — donc quinze rangées de libellés sont restées vides depuis le
            # début. Le banc les remplit toutes, avec des chaînes qui disent leur niveau, pour
            # voir lesquelles le contrôleur expose réellement.
            if etage != "test":
                niveaux = (0,)
            else:
                tl = test_level()
                niveaux = range(TEST_LABEL_LEVELS) if tl < 0 else (tl,)
            for niv in niveaux:
                envoi = (_test_labels(labels, {"kind": kind, "char_length": label_chars(),
                                               "extended": False, "level": niv})
                         if etage == "test" else labels)
                for data in proto.name_responses(kind, envoi, matrix=layer - 1, level=niv,
                                                 char_length=label_chars(), extended=False,
                                                 first=1):
                    if not _send(conn, proto.pack(data)):
                        return n
                    n += 1
            _published[cle] = set(tables.get((etage, role)) or {})
    return n


def write_allow_list():
    raw = settings.get("swp08_write_allow") or ""
    return {p.strip() for p in str(raw).replace(";", ",").split(",") if p.strip()}


def _write_allowed(addr):
    """Vrai si cette adresse a le droit d'ÉCRIRE (affectation d'un slot).

    Mêmes règles et mêmes semantiques que `emberplus._write_allowed` — une seule règle à
    retenir pour les deux protocoles de pupitre. Le protocole ne prévoit aucune
    authentification, donc on restreint par adresse : le pupitre déclaré écrit, tout le monde
    peut lire, et un client de diagnostic ne casse rien.

    Ce qui se joue ici est plus lourd que côté Ember+ : une écriture sur le layer d'affectation
    DÉPLACE un matériel, donc renumérote tous ses signaux et toutes ses voies (§12.8). C'est un
    déménagement de parc accessible en un crosspoint.

    Liste VIDE = aucune restriction, pour ne rien casser sur une installation existante — mais
    l'état est journalisé au démarrage, faute de quoi une protection jamais configurée serait
    exactement le « livré mais pas en service » qui a déjà coûté cher à ce projet."""
    allow = write_allow_list()
    if not allow:
        return True
    return (addr[0] if isinstance(addr, (tuple, list)) else str(addr)) in allow


def _dual_status_byte():
    return _int_setting("swp08_dual_status", 0x02, 0, 255)


# Les commandes qu'on sert vraiment, dans l'ordre du §10.1. NE PAS y ajouter ce qu'on ne
# traite pas : la réponse 62 est une promesse, et un contrôleur qui s'y fie enverrait alors des
# trames qu'on ignorerait en silence. Manquent volontairement les salvos (120 à 125) et le dump
# BYTE (22), non implémentés.
SERVED_COMMANDS = (
    proto.CMD_INTERROGATE, proto.CMD_CONNECT, proto.CMD_TALLY, proto.CMD_CONNECTED,
    proto.CMD_DUAL_STATUS_REQ, proto.CMD_DUAL_STATUS_RESP,
    proto.CMD_TALLY_DUMP_REQ, proto.CMD_TALLY_DUMP_WORD,
    proto.CMD_PROTO_IMPL_REQ, proto.CMD_PROTO_IMPL_RESP,
    proto.CMD_GET_SOURCE_NAMES, proto.CMD_GET_DEST_NAMES,
    proto.CMD_SOURCE_NAMES_RESPONSE, proto.CMD_DEST_NAMES_RESPONSE,
    proto.CMD_EXT_INTERROGATE, proto.CMD_EXT_CONNECT,
    proto.CMD_EXT_TALLY, proto.CMD_EXT_CONNECTED,
    proto.CMD_EXT_TALLY_DUMP_REQ,
    proto.CMD_EXT_GET_SOURCE_NAMES, proto.CMD_EXT_GET_DEST_NAMES,
    proto.CMD_EXT_SOURCE_NAMES_RESPONSE, proto.CMD_EXT_DEST_NAMES_RESPONSE,
)


def _handle_routing(conn, addr, payload):
    """Sert les commandes d'ÉTAT du routeur. Rend False si la trame n'est pas pour nous, True si
    elle a été traitée, et la chaîne « nak » si elle a été traitée mais REFUSÉE — auquel cas
    l'appelant refuse la trame au niveau liaison au lieu de l'acquitter.

    Sans elles, rien d'autre ne démarre : le pupitre interroge l'état du contrôleur (08) toutes
    les dix secondes et, faute de réponse, ne considère jamais le routeur comme vivant — donc
    ne demande jamais les noms. C'est ce qu'a montré le premier essai réel.

    On ne COMMUTE pas par ce canal : le routage vit sur Ember+, et deux protocoles autorisés à
    écrire le même crosspoint donneraient deux vérités. Un `connect` reçu est donc refusé — mais
    en RÉPONDANT l'état vrai, pour que le point de croisement optimiste du pupitre claque en
    arrière au lieu de mentir (même règle qu'au §12.3 côté Ember+)."""
    t0 = time.monotonic()       # arrivée de la trame — origine de la fenêtre d'occultation
    r = proto.decode_routing(payload)
    if not r:
        return False
    if r["kind"] == "dual_status":
        _send(conn, proto.pack(proto.dual_status(_dual_status_byte())))
        return True
    if r["kind"] == "proto_impl":
        # Ce qu'on sert RÉELLEMENT, pas ce que la spec définit. Le pupitre visé ne le demande
        # jamais (aucune trame 61 relevée), mais un contrôleur qui s'enquiert avant de parler
        # mérite une réponse exacte plutôt que notre silence.
        _send(conn, proto.pack(proto.proto_impl(SERVED_COMMANDS)))
        log.info("swp08: %s — implémentation demandée → %d commande(s)", addr, len(SERVED_COMMANDS))
        return True
    tables, err = model()
    if err:
        log.warning("swp08: %s — état indisponible : %s", addr, err)
        return True
    etage = _stage_of(r["matrix"] + 1, r["level"] + 1)
    tal = tables.get((etage, "tally")) or {}
    if r["kind"] == "interrogate":
        src = tal.get(r["dest"] + 1)          # base 0 sur le fil
        if src is None:
            return True                        # destination sans source : pas de tally menteur
        _send_tally(conn, r["matrix"], r["level"], r["dest"], src - 1)
        return True
    if r["kind"] == "connect":
        if etage == "test":
            # Le banc d'essai prouve la boucle complète — connect reçu, état modifié, `04`
            # renvoyé, tally cohérent au dump suivant — en mémoire, sans toucher au matériel.
            # Et depuis le 2026-07-31 il prouve aussi le REFUS, que le matériel ne sait pas
            # produire sur commande : les sources à partir de `TEST_REFUS_MIN` refusent toujours.
            dest, src = r["dest"] + 1, (r["source"] or 0) + 1
            if not (1 <= dest <= TEST_SIZE and 1 <= src <= TEST_SIZE):
                log.info("swp08: %s — TEST hors plage (dest %d, src %d, max %d)",
                         addr, dest, src, TEST_SIZE)
                return True
            if src >= TEST_REFUS_MIN:
                log.info("swp08: %s — TEST dest %d ← src %d : REFUSÉ (source impossible, "
                         "mode « %s »)", addr, dest, src, _refus_mode())
                _answer_xpt(conn, t0, r["matrix"], r["level"], r["dest"],
                            r["source"] or 0, _test_tally.get(dest, dest) - 1)
                return "nak" if _refus_mode() == "nak" else True
            _test_tally[dest] = src
            model(force=True)
            log.info("swp08: %s — TEST dest %d ← src %d (accepté)", addr, dest, src)
            _send_tally(conn, r["matrix"], r["level"], r["dest"],
                        r["source"] or 0, connected=True)
            # Et à TOUS les autres clients, en diffusion spontanée (§8.2.2). Sans ça un banc à
            # plusieurs pupitres ment : celui qui n'a pas commuté continue d'afficher l'ancienne
            # source. C'est aussi ce qui permet de provoquer, depuis la machine, un changement
            # que le pupitre voit arriver « d'ailleurs » — le seul moyen d'éprouver comment il
            # traite un croisement modifié par un tiers.
            with _lock:
                autres = [c for a, c in _clients.items() if c is not conn]
            for c in autres:
                _send_tally(c, r["matrix"], r["level"], r["dest"],
                            r["source"] or 0, connected=True)
            return True
        ok = _apply_assign(conn, addr, r, tal) if etage == "assign" \
            else _apply_signal(conn, addr, r, tal)
        if ok is False and _refus_mode() == "nak":
            return "nak"
        return True
    if r["kind"] == "tally_dump":
        # Découpé en tranches CONTIGUËS de 64 : le format n'annonce qu'une destination de
        # départ suivie de N sources consécutives, donc un trou impose un nouveau message.
        envoyes = 0
        for run in _runs(sorted(tal)):
            for i in range(0, len(run), proto.TALLY_DUMP_MAX):
                bout = run[i:i + proto.TALLY_DUMP_MAX]
                data = proto.tally_dump_word(r["matrix"], r["level"], bout[0] - 1,
                                             [tal[d] - 1 for d in bout])
                _send(conn, proto.pack(data))
                envoyes += 1
        log.info("swp08: %s — dump matrice %d niveau %d (%s) → %d message(s), %d tally",
                 addr, r["matrix"] + 1, r["level"] + 1,
                 STAGE_LABELS.get(etage, "?"), envoyes, len(tal))
        return True
    return False


def _apply_signal(conn, addr, r, tal):
    """Commute un signal depuis le contrôleur (layers 1 à 8).

    Le routage vit ICI depuis le 2026-07-31, et plus dans les matrices Ember+. La raison est
    celle qui a fait choisir SW-P-08 : une matrice Ember+ se câble à la main au contrôleur,
    exactement comme un paramètre, alors qu'un routeur s'ingère en bloc. Garder les deux
    revenait à refaire le travail qu'on cherchait à éviter — et à entretenir deux vérités sur
    le même crosspoint.

    On ne retraduit rien : `ipg_io.apply_connect` connaît déjà les numéros émis, les essences
    et les refus du matériel. Une seconde traduction serait une seconde vérité."""
    t0 = time.monotonic()       # arrivée de la commande — origine de la fenêtre d'occultation
    layer = r["matrix"] + 1
    plan = _CANON_OF_LEVEL.get(layer)
    ipg_io, err = _ipg()
    if not plan or err:
        log.info("swp08: %s — layer %d sans grille canonique (%s)", addr, layer, err or "hors plan")
        return True
    canon, ess = plan
    dec = ipg_io.AUDIO2_OFFSET if ess == "audio2" else 0
    if not _write_allowed(addr):
        log.warning("swp08: %s — commutation REFUSÉE : adresse hors de `swp08_write_allow`", addr)
        vrai = tal.get(r["dest"] + 1)
        if vrai is not None:
            _answer_xpt(conn, t0, r["matrix"], r["level"], r["dest"],
                        r["source"] or 0, vrai - 1)
        return False
    # L'état du parc : celui du service Ember+, qui le tient à jour et le met en cache. Le
    # reconstruire ici coûterait plusieurs secondes par crosspoint.
    try:
        from app import core_plugins
        svc = core_plugins.module("emberplus")
        state = svc._io_state() if svc else None
    except Exception as e:
        log.warning("swp08: %s — état du parc indisponible : %s", addr, e)
        return True
    if not state:
        log.info("swp08: %s — état du parc vide, commutation ignorée", addr)
        return True
    tgt = r["dest"] + dec
    src = [(r["source"] or 0) + dec]
    try:
        ok, touche = ipg_io.apply_connect(canon, tgt, src, "connect", state)
    except Exception as e:
        log.warning("swp08: %s — commutation a levé : %s", addr, e)
        return True
    log.info("swp08: %s — %s dest %d ← src %d : %s%s", addr, canon, r["dest"] + 1,
             (r["source"] or 0) + 1, "appliqué" if ok else "REFUSÉ par le matériel",
             " (%s)" % touche if touche else "")
    if ok:
        audit_log("swp08", "connect", "%s dest %d ← src %d" % (canon, r["dest"] + 1,
                                                               (r["source"] or 0) + 1),
                  user_id=None, username=SWP08_ACTOR)
    # ── Réponse, et c'est le point important ──────────────────────────────────────────
    # Le contrôleur affiche son crosspoint dès le clic, en pariant sur le succès. Tant qu'on ne
    # répond pas, il reste EN ATTENTE — et la rediffusion de fond met plusieurs secondes, le
    # temps de reconstruire le modèle. Un refus doit donc être annoncé sans attendre celle-ci,
    # sinon l'opérateur croit que ça a marché (§12.3). Le comment est dans `_answer_xpt` : le
    # protocole n'ayant pas de refus, on lève l'attente puis on dément.
    #
    # Dans les deux cas la rediffusion qui suit confirmera sur l'état relu du matériel, qui
    # reste seul juge.
    demande = r["source"] or 0
    if ok:
        reel = demande
    else:
        vrai = tal.get(r["dest"] + 1)
        reel = (vrai - 1) if vrai is not None else (ipg_io.PSEUDO_NONE - 1)
    _answer_xpt(conn, t0, r["matrix"], r["level"], r["dest"], demande, reel)
    threading.Thread(target=notify_change, daemon=True).start()
    return ok


def _apply_assign(conn, addr, r, tal):
    """Pose un matériel sur un slot depuis le pupitre (layer « affectation »).

    Contrairement au routage des signaux, l'affectation n'a QU'UN propriétaire — la couche IPG
    — et le service Ember+ y renvoie déjà les écritures de sa grille 1010. Le layer 9 emprunte
    le même chemin : deux portes, une seule serrure, donc pas de seconde vérité.

    ⚠ Un déplacement RENUMÉROTE tout le matériel concerné (`100×slot + n` sur ses voies comme
    sur ses connecteurs, et son sous-arbre Ember+ change de chemin). Le §12.8 décrit ça comme
    un déménagement hors service, pas un geste de production. C'est un pouvoir réel qu'on donne
    au pupitre, d'où le réglage `swp08_allow_assign` pour le retirer en exploitation."""
    t0 = time.monotonic()       # arrivée de la commande — origine de la fenêtre d'occultation
    slot = r["dest"] + 1
    ancien = tal.get(slot)
    if not _write_allowed(addr):
        log.warning("swp08: %s — affectation REFUSÉE : adresse hors de `swp08_write_allow`",
                    addr)
        if ancien is not None:
            _answer_xpt(conn, t0, r["matrix"], r["level"], r["dest"],
                        r["source"] or 0, ancien - 1)
        return False
    if not bool(settings.get("swp08_allow_assign")):
        log.info("swp08: %s — affectation refusée (slot %d) : `swp08_allow_assign` est faux",
                 addr, slot)
        if ancien is not None:
            _answer_xpt(conn, t0, r["matrix"], r["level"], r["dest"],
                        r["source"] or 0, ancien - 1)
        return False
    ipg_io, err = _ipg()
    if err or not _contributor:
        log.warning("swp08: %s — affectation impossible : %s", addr, err or "couche IPG absente")
        return True
    src = (r["source"] or 0) + 1
    # Source 1 = « Disconnect » (PSEUDO_NONE) : c'est le geste qui VIDE le slot. Les matériels
    # commencent à 11 (DEV_SRC_OFFSET + 1), donc tout ce qui est en dessous vide.
    numero = src - ipg_io.DEV_SRC_OFFSET
    libere = numero <= 0
    payload = {"slot": slot, "number": None if libere else numero}
    try:
        status, data = tools.call(_contributor, "ipg/assign", "POST", payload,
                                  actor=SWP08_ACTOR, timeout=15)
    except Exception as e:
        log.warning("swp08: %s — renvoi de l'affectation a levé : %s", addr, e)
        return True
    ok = status == 200 and isinstance(data, dict) and not data.get("error")
    if not ok:
        log.info("swp08: %s — affectation refusée par la couche IPG → %s %s", addr, status, data)
    else:
        quoi = "libéré" if libere else "← matériel n° %d (source %d)" % (numero, src)
        log.info("swp08: %s — slot %d %s", addr, slot, quoi)
        audit_log("swp08", "assign", "slot %d %s" % (slot, quoi),
                  user_id=None, username=SWP08_ACTOR)
    # L'état a bougé : le modèle en cache est périmé, on le reconstruit AVANT de répondre pour
    # que le tally renvoyé soit le vrai — un pupitre qui reçoit l'ancien état croit à un échec.
    tables, _ = model(force=True)
    apres = tables.get(("assign", "tally")) or {}
    # ── Un déplacement change DEUX croisements ────────────────────────────────────────
    # L'affectation est du 1 pour 1 : poser un matériel déjà placé ailleurs le DÉPLACE, donc
    # son ancien slot se vide. Ne confirmer que la destination demandée laisserait le pupitre
    # afficher le matériel à deux endroits — ce qui est justement l'état que le modèle interdit.
    # On renvoie donc un `04` pour CHAQUE slot dont l'occupant a changé.
    # Refus : rien n'a changé, donc la boucle ci-dessous n'annoncerait RIEN — et le pupitre
    # resterait en attente sur le slot demandé. On le détrompe explicitement, sur son état réel.
    if not ok:
        vrai = apres.get(slot)
        _answer_xpt(conn, t0, r["matrix"], r["level"], r["dest"], r["source"] or 0,
                    (vrai if vrai is not None else ipg_io.PSEUDO_NONE) - 1)
    for s in sorted(set(tal) | set(apres)):
        avant, maintenant = tal.get(s), apres.get(s)
        if avant == maintenant:
            continue
        # Slot vidé : on l'annonce sur le pseudo-signal « Aucun », le même que la grille 1010.
        src_num = maintenant if maintenant is not None else ipg_io.PSEUDO_NONE
        _send_tally(conn, r["matrix"], r["level"], s - 1,
                                           src_num - 1, connected=True)
        log.info("swp08: slot %d → %s", s,
                 "matériel %d" % maintenant if maintenant else "vide")
    # Les AUTRES clients, et surtout les libellés : un déplacement renumérote tout le matériel
    # concerné, donc ses noms changent aussi. En fond pour ne pas retarder la réponse.
    threading.Thread(target=notify_change, daemon=True).start()
    return ok


def _runs(nums):
    """Découpe une suite triée en tranches d'entiers consécutifs."""
    out, cur = [], []
    for n in nums:
        if cur and n != cur[-1] + 1:
            out.append(cur)
            cur = []
        cur.append(n)
    if cur:
        out.append(cur)
    return out


def _serve_client(conn, addr):
    """Un client. Le protocole exige un ACK par message reçu, y compris sur IP (Appendix 2) —
    c'est la première chose qu'on renvoie, avant même de préparer la réponse : le pupitre
    retransmet cinq fois en l'absence d'acquittement, et une réponse lente ne doit pas être
    prise pour une réponse perdue."""
    buf = b""
    conn.settimeout(CLIENT_IDLE_S)
    try:
        while not _stop.is_set():
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if bool(settings.get("swp08_trace")):
                # Trace BRUTE, réglage `swp08_trace`. Éteinte par défaut : elle journalise tout
                # ce qui entre, y compris les battements de cœur, donc elle noie le journal.
                # Elle existe parce qu'un « il ne se passe rien » a deux causes indiscernables —
                # le contrôleur n'envoie rien, ou nous ne comprenons pas ce qu'il envoie.
                log.info("swp08: %s ← %s", addr, proto.hexstring(chunk[:64]))
            events, buf = proto.unpack(buf)
            for kind, payload in events:
                if kind == "erreur":
                    log.info("swp08: %s — trame rejetée : %s", addr, payload)
                    _send(conn, proto.FRAME_NAK)
                    continue
                if kind in ("ack", "nak"):
                    continue            # acquittements du client : rien à faire de plus
                # D'ordinaire on acquitte AVANT de traiter : le pupitre retransmet cinq fois en
                # l'absence d'acquittement, et une réponse lente ne doit pas passer pour une
                # réponse perdue. Le mode « nak » impose l'inverse sur les seules commutations —
                # refuser une trame qu'on vient d'acquitter n'aurait aucun sens. La décision
                # doit donc être rendue avant que la retransmission ne parte : c'est tenable au
                # banc d'essai, qui tranche en mémoire, et c'est bien pour ça qu'on l'y éprouve
                # avant d'en faire quoi que ce soit sur du matériel.
                differe = (_refus_mode() == "nak" and payload
                           and payload[0] in (proto.CMD_CONNECT, proto.CMD_EXT_CONNECT))
                if not differe:
                    _send(conn, proto.FRAME_ACK)
                if _absorb_names(addr, payload):
                    if differe:
                        _send(conn, proto.FRAME_ACK)
                    continue
                verdict = _handle_routing(conn, addr, payload)
                if verdict:
                    if differe:
                        _send(conn, proto.FRAME_NAK if verdict == "nak" else proto.FRAME_ACK)
                    continue
                if differe:
                    _send(conn, proto.FRAME_ACK)
                req = proto.decode_request(payload)
                if not req:
                    log.info("swp08: %s — commande %02X non gérée (ignorée)",
                             addr, payload[0] if payload else 0)
                    continue
                with _lock:
                    _status["requests"] += 1
                frames, err = responses_for(req)
                if err:
                    log.warning("swp08: %s — réponse impossible : %s", addr, err)
                    continue
                for f in frames:
                    _send(conn, f)
                with _lock:
                    _status["labels_sent"] += len(frames)
                # La LARGEUR demandée et le jeu de commandes manquaient à cette ligne. Ce sont
                # pourtant les deux seules choses qu'on ne peut pas deviner du contrôleur, et
                # celles dont dépend le nommage sur plusieurs niveaux : savoir s'il réclame 4,
                # 8 ou 12 caractères, et s'il passe par le jeu étendu.
                log.info("swp08: %s — %s matrice %d niveau %d (%s) %d car.%s → %d message(s)",
                         addr, req["kind"], req["matrix"] + 1, req["level"] + 1,
                         STAGE_LABELS.get(_stage_of(req["matrix"] + 1, req["level"] + 1), "?"),
                         req["char_length"], " étendu" if req.get("extended") else "", len(frames))
    finally:
        try:
            conn.close()
        except OSError:
            pass
        with _lock:
            _clients.pop(addr, None)
            _status["clients"] = len(_clients)


# Commandes dont on NE trace PAS l'émission : les libellés. Une rediffusion en pousse plus de
# quinze cents d'un coup, ce qui noierait le seul trafic qu'on cherche à lire.
_TRACE_MUETTES = frozenset((proto.CMD_SOURCE_NAMES_RESPONSE, proto.CMD_DEST_NAMES_RESPONSE,
                            proto.CMD_UMD_LABELS_RESPONSE, proto.CMD_EXT_SOURCE_NAMES_RESPONSE,
                            proto.CMD_EXT_DEST_NAMES_RESPONSE))


def _send(conn, data):
    # Trace du SORTANT. Elle a manqué longtemps, et ça coûte cher : jusqu'au 2026-07-31 on a
    # raisonné sur des trames qu'on n'avait jamais lues, en supposant correct ce qu'on émettait.
    if bool(settings.get("swp08_trace")) and len(data) > 3 and data[2] not in _TRACE_MUETTES:
        log.info("swp08: → %s", proto.hexstring(data[:32]))
    try:
        conn.sendall(data)
        return True
    except OSError as e:
        log.info("swp08: émission échouée : %s", e)
        return False


# Le contrôleur OCCULTE les tallies pendant « approx. 100mS » après avoir émis une commutation
# (SW-P-88 §7.1) : il affiche d'emblée ce qu'il a demandé, et jette les tallies de cette fenêtre
# pour qu'un message en vol n'écrase pas son pari. C'est ce qui date le DÉMENTI de `_answer_xpt`
# — envoyé plus tôt, il serait jeté.
#
# Attention à ne pas relire cette constante comme l'explication du refus resté en attente : elle
# ne l'était pas. Attendre la fin de la fenêtre AVANT d'annoncer la source réelle a été essayé le
# 2026-07-31 et n'a rien changé, y compris sur un refus parti sept secondes après la commande.
# La marge est large parce que le pupitre ne publie pas la sienne et que la spécification ne
# donne qu'un ordre de grandeur.
XPT_BLANKING_S = 0.6


def _answer_xpt(conn, t0, matrix, level, dest, demande, reel):
    """Répond à une commutation en annonçant l'état RÉEL, et rien d'autre. Chemin unique : une
    réussite se confirme, un refus annonce ce qui est resté en place.

    ⚠ **Le pupitre n'a pas de case pour un refus, et on a cherché longtemps.** Ce qu'il affiche
    en attente n'est pas une commande non soldée qu'une trame pourrait clore : c'est l'affichage
    permanent de « demandé ≠ réel ». Trois mesures indépendantes du 2026-07-31 le montrent — la
    marque APPARAÎT au clic alors qu'on n'émet rien (mode « muet ») ; elle S'EFFACE si on
    confirme la source demandée ; elle REVIENT dès qu'on annonce une autre source, à 600 ms
    comme à 12 s, avec ou sans TALLY préalable. Il n'existe donc aucune trame qui distingue « la
    demande est abandonnée » de « l'état diffère », parce que pour lui c'est la même chose.

    Conséquence pratique, et c'est le choix qu'on assume : **on ne ment pas**. Confirmer d'abord
    la source demandée pour lever la marque, puis se dédire, a été essayé — le pupitre affiche
    alors un succès pendant tout le délai, puis retombe à l'orange. On y gagnait un mensonge et
    rien d'autre. Une seule trame part donc, portant la vérité.

    Le §15.12 de EMBERPLUS-IPG.md tient le détail des essais, à lire AVANT d'en tenter d'autres :
    quatre mécanismes de refus, un témoin muet, contrôleur actif, `Acknowledge First` et
    `Honor Acknowledge` armés. Le vrai correctif est en amont — ne pas produire de commutation
    insatisfaisable — et il ne se joue pas dans ce fichier.

    `swp08_refus_mode` garde les mécanismes éprouvés, pour un pupitre qui, lui, en tiendrait
    compte. Ils sont sans effet sur celui-ci."""
    if reel != demande:
        mode = _refus_mode()
        if mode == "muet":
            return True                     # témoin : on laisse le pupitre seul avec sa demande
        if mode == "nak":
            return True                     # la trame elle-même est refusée, cf. `_serve_client`
        if mode == "oor":
            _send_tally(conn, matrix, level, dest, OOR_SOURCE)
            return True

    def _annoncer():
        # Jamais avant la fin de la fenêtre d'occultation du §7.1 : le pupitre jette les retours
        # des ~100 ms qui suivent sa commande, donc répondre plus tôt revient à ne pas répondre.
        # `swp08_dementi_ms` permet d'allonger encore, ce qui n'a servi qu'aux essais.
        cible = max(XPT_BLANKING_S, _int_setting("swp08_dementi_ms", 600, 0, 60000) / 1000.0)
        reste = cible - (time.monotonic() - t0)
        if reste > 0:
            time.sleep(reste)
        # UN SEUL CONNECTED, exactement ce qu'émet `_notify_once`. Le §8.2.2 en fait le message
        # « issued spontaneously by the controller on all ports » : il AFFIRME une route, il ne
        # se compare à rien. Le TALLY, lui, est la réponse à une interrogation d'état (§8.2.1),
        # que le pupitre confronte à ce qu'il a commandé — on n'en émet donc pas ici.
        _send_tally(conn, matrix, level, dest, reel, connected=True)

    threading.Thread(target=_annoncer, daemon=True).start()
    return True


_hors_portee = set()        # numéros déjà signalés, pour ne pas noyer le journal


def _send_tally(conn, matrix, level, dest, source, *, connected=False, bad=False):
    """Émet un tally/connected, ou RENONCE si les numéros dépassent ce que les commandes
    standard savent adresser (1023, cf. `proto.tally`). Renoncer bruyamment vaut mieux que
    replier en silence : au-delà du slot 10, le pupitre afficherait des croisements sur les
    mauvaises destinations sans que rien ne le signale."""
    # On n'emploie l'ÉTENDU que si le standard ne suffit pas. Le standard est éprouvé au banc
    # sur ce pupitre ; l'étendu ne l'est pas — sa disposition vient du module Companion, comme
    # les commandes de noms. Basculer tout le parc dessus risquerait de casser ce qui marche
    # pour un gain nul en dessous de 1024.
    ext = max(dest, source) > proto.STD_SIGNAL_MAX
    if bad and ext:
        # Le jeu étendu n'a pas de multiplicateur, donc pas de bit « source mauvaise ». On le
        # dit plutôt que de laisser croire à un refus signalé.
        log.warning("swp08: refus NON signalable au-delà de %d (dest %d, source %d) — le jeu "
                    "étendu n'a pas de bit « source mauvaise »", proto.STD_SIGNAL_MAX, dest, source)
    try:
        return _send(conn, proto.pack(proto.tally(matrix, level, dest, source,
                                                  connected=connected, extended=ext, bad=bad)))
    except ValueError as e:
        cle = (dest, source)
        if cle not in _hors_portee:
            _hors_portee.add(cle)
            log.warning("swp08: croisement non annonçable — %s", e)
        return False


_last_assign = {}       # {layer: {dest: source}} déjà diffusé — sert à n'annoncer que les écarts
                        # ET à repérer les destinations DISPARUES, qu'il faut déconnecter.


_notify_lock = threading.Lock()
_notify_pending = threading.Event()


def notify_change():
    """Diffusion COALESCÉE : une seule à la fois, et une demande reçue pendant qu'elle tourne
    en déclenche exactement une de plus, pas une par appel.

    Sans ça, la course est garantie : une diffusion reconstruit le modèle, ce qui réinterroge
    tout le parc et prend plusieurs secondes. Libérer trois slots en vingt secondes lançait
    donc trois diffusions concurrentes, qui comparaient chacune l'état frais au MÊME repère
    global — et la plus lente annonçait au pupitre une transition déjà périmée. Constaté le
    2026-07-30 : un slot vidé se rallumait tout seul une seconde plus tard, non pas parce que
    la libération avait échoué, mais parce qu'on la démentait nous-mêmes."""
    _notify_pending.set()
    if not _notify_lock.acquire(blocking=False):
        return 0                      # une diffusion tourne déjà : elle repassera pour nous
    total = 0
    try:
        while _notify_pending.is_set():
            _notify_pending.clear()
            total += _notify_once()
    finally:
        _notify_lock.release()
    return total


def _notify_once():
    """Un tour de diffusion. À n'appeler QUE depuis `notify_change`, qui en sérialise l'accès.

    Il ne redemande jamais les noms (`NamesUpdated` n'est pas implémenté chez lui) et ne
    refait un dump qu'à sa guise. Une affectation changée depuis notre écran resterait donc
    invisible — c'est ce qui a été constaté en déplaçant un SNP sans que rien ne bouge.

    On diffuse donc, comme la spec l'autorise pour le `04` (« *issued spontaneously by the
    controller on all ports, effectively broadcast* ») : les croisements d'affectation qui ont
    changé, puis TOUS les libellés. Les libellés parce qu'un déplacement de slot renumérote le
    matériel entier — ses voies comme ses connecteurs — donc ce ne sont pas trois lignes qui
    changent, c'est tout son nommage."""
    global _last_assign
    tables, err = model(force=True)
    if err:
        log.info("swp08: parc indisponible, diffusion annulée : %s", err)
        return 0
    with _lock:
        conns = list(_clients.values())
    if not conns:
        _last_assign = dict(tables.get(("assign", "tally")) or {})
        return 0
    ipg_io, _ = _ipg()
    vide = getattr(ipg_io, "PSEUDO_NONE", 1) if ipg_io else 1
    # Diff des croisements sur TOUS les layers, pas seulement l'affectation : quand un matériel
    # déménage, les destinations de son ancien slot cessent d'exister et le pupitre continuerait
    # de les afficher commutées. Une destination disparue est annoncée « déconnectée ».
    nouveau = {}
    envoyes = 0
    for layer, stage, _ess in LEVEL_PLAN:
        etage = _stage_of(layer)
        apres = tables.get((etage, "tally")) or {}
        nouveau[layer] = dict(apres)
        avant = _last_assign.get(layer) or {}
        for dest in sorted(set(avant) | set(apres)):
            a, b = avant.get(dest), apres.get(dest)
            if a == b:
                continue
            src = b if b is not None else vide
            for conn in conns:
                if _send_tally(conn, layer - 1, 0, dest - 1, src - 1, connected=True):
                    envoyes += 1
    for conn in conns:
        envoyes += push_names(conn, tables, clear_stale=True)
    _last_assign = nouveau
    if envoyes:
        log.info("swp08: parc modifié — %d trame(s) diffusée(s) à %d client(s)",
                 envoyes, len(conns))
    return envoyes


def _push_on_connect(conn, addr):
    """Petite temporisation avant de pousser : laisser le pupitre finir sa propre séquence
    d'ouverture (état du contrôleur, dumps) évite d'entrelacer nos trames avec les siennes
    pendant qu'il s'installe."""
    time.sleep(2.0)
    try:
        n = push_names(conn)
    except Exception as e:
        log.warning("swp08: %s — poussée des libellés échouée : %s", addr, e)
        return
    if n:
        log.info("swp08: %s — %d trame(s) de libellés poussée(s) spontanément", addr, n)


def _server_loop(p):
    global _sock
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", p))
        srv.listen(MAX_CLIENTS)
        srv.settimeout(ACCEPT_TIMEOUT_S)
    except OSError as e:
        with _lock:
            _status["last_error"] = "écoute sur :%d impossible — %s" % (p, e)
            _status["running"] = False
        log.error("swp08: %s", _status["last_error"])
        return
    _sock = srv
    with _lock:
        _status.update(running=True, port=p, last_error=None, started_at=time.time())
    allow = write_allow_list()
    log.info("swp08: écoute sur :%d — écriture %s", p,
             "restreinte à %s" % ", ".join(sorted(allow)) if allow
             else "OUVERTE À TOUS (`swp08_write_allow` vide)")
    while not _stop.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with _lock:
            trop = len(_clients) >= MAX_CLIENTS
        if trop:
            # Plafond de la spec. On ferme franchement plutôt que d'accepter et de se taire :
            # un client silencieux est bien plus difficile à diagnostiquer qu'un refus net.
            log.warning("swp08: %s refusé — %d clients déjà connectés", addr, MAX_CLIENTS)
            try:
                conn.close()
            except OSError:
                pass
            continue
        if bool(settings.get("swp08_push_names")):
            # Poussée à la connexion, en fond : le pupitre ne demandera jamais nos noms, mais
            # il accepte qu'on les lui envoie. En fond parce que la construction du modèle peut
            # prendre quelques secondes à froid, et que l'accueil du client ne doit pas attendre.
            threading.Thread(target=_push_on_connect, args=(conn, addr), daemon=True).start()
        t = threading.Thread(target=_serve_client, args=(conn, addr), daemon=True)
        with _lock:
            _clients[addr] = conn        # la SOCKET, pas le fil : c'est elle qui sert à diffuser
            _status["clients"] = len(_clients)
        t.start()
        log.info("swp08: client %s connecté", addr)
    try:
        srv.close()
    except OSError:
        pass
    with _lock:
        _status.update(running=False, clients=0)
    log.info("swp08: arrêt de l'écoute")


def start(p):
    global _thread
    stop()
    if not (1 <= p <= 65535):
        with _lock:
            _status["last_error"] = "port non configuré"
        return False
    _stop.clear()
    _thread = threading.Thread(target=_server_loop, args=(p,), daemon=True)
    _thread.start()
    return True


def stop():
    global _sock, _thread
    _stop.set()
    if _sock is not None:
        try:
            _sock.close()
        except OSError:
            pass
        _sock = None
    if _thread is not None and _thread.is_alive():
        _thread.join(timeout=2.0)
    _thread = None
    with _lock:
        _status.update(running=False, clients=0)


def is_running():
    with _lock:
        return bool(_status["running"])


def status_dict():
    with _lock:
        return dict(_status)


def _prime():
    """Préchauffe le modèle ET AMORCE LE REPÈRE des croisements.

    Sans cet amorçage, `_last_assign` reste vide jusqu'à la première diffusion : le premier
    changement ne voit donc que des ARRIVÉES, jamais les disparitions, et les croisements de
    l'ancien slot restent affichés au pupitre. Constaté au banc le 2026-07-30 en déplaçant un
    SNP du slot 11 au 12 — les libellés se sont bien effacés (leur repère, lui, est renseigné
    par chaque poussée, donc dès la connexion du client) mais pas les croisements.

    C'est la même asymétrie qui rendait le défaut trompeur : deux mécanismes voisins, deux
    états initiaux différents."""
    global _last_assign
    tables, err = model(force=True)
    if err:
        return
    _last_assign = {layer: dict(tables.get((_stage_of(layer), "tally")) or {})
                    for layer, _st, _e in LEVEL_PLAN}
    log.info("swp08: modèle préchauffé, repère des croisements amorcé (%d layer(s))",
             len(_last_assign))


def boot():
    if bool(settings.get("swp08_enabled")):
        p = port()
        if p:
            start(p)
            # Préchauffage en fond : la première construction coûte plusieurs secondes, et
            # elle ne doit pas tomber sur le premier client. Le démarrage, lui, n'attend pas.
            threading.Thread(target=_prime, daemon=True).start()
        else:
            log.info("swp08: activé mais sans port — rien n'écoute")


# ═════════════════════════════════════════════════════════════════════
# Routes
# ═════════════════════════════════════════════════════════════════════

def register_routes(bp):
    from flask import request, jsonify
    from app.auth import require_login, require_perm

    @bp.route("/api/swp08/status", methods=["GET"])
    @require_login
    def swp08_status():
        out = status_dict()
        # TOUS les réglages, pas seulement ceux du transport. Convention : `swp08_X` se lit en
        # `X_setting` et s'écrit par le champ `X` d'`apply`. Les deux routes doivent rester
        # SYMÉTRIQUES : un réglage écrivable mais non relu ferait qu'un simple « Enregistrer »
        # écraserait la valeur en base par le défaut affiché à l'écran.
        out.update(enabled_setting=bool(settings.get("swp08_enabled")),
                   port_setting=port(), label_chars_setting=label_chars(),
                   extended_setting=extended(), matrices_setting=matrices(),
                   allow_assign_setting=bool(settings.get("swp08_allow_assign")),
                   push_names_setting=bool(settings.get("swp08_push_names")),
                   dual_status_setting=_dual_status_byte(),
                   test_setting=bool(settings.get("swp08_test")),
                   test_matrix_setting=_int_setting("swp08_test_matrix", 1, 1, 16),
                   sdi_per_slot_setting=sdi_per_slot(),
                   ip_per_slot_setting=ip_per_slot(),
                   signal_format_setting=_fmt("swp08_signal_format", "{short} {kind}{n}"),
                   lane_format_setting=_fmt("swp08_lane_format", "{short} V{lane}"),
                   slot_format_setting=_fmt("swp08_slot_format", "IPG{slot} - {n}"),
                   unused_label_setting=_fmt("swp08_unused_label", "."),
                   levels=[{"level": lvl, "stage": st, "essence": es,
                            "label": "%s %s" % (STAGE_LABELS[st], ESSENCE_LABELS[es])}
                           for lvl, st, es in LEVEL_PLAN])
        tables, err = model()
        out["source_error"] = err
        out["counts"] = {"%s/%s" % k: len(v) for k, v in sorted(tables.items())}
        return jsonify(out)

    @bp.route("/api/swp08/received", methods=["GET"])
    @require_login
    def swp08_received():
        """Les libellés que le CONTRÔLEUR nous a poussés — clé « matrice/niveau/type ».
        Purement documentaire : c'est ce qui permet de comparer son plan de nommage au nôtre."""
        return jsonify(received_names())

    @bp.route("/api/swp08/preview", methods=["GET"])
    @require_login
    def swp08_preview():
        """Ce qui PARTIRAIT, sans qu'aucune socket ne s'ouvre — et en hexadécimal commenté.

        C'est le seul moyen d'éprouver les commandes de noms tant qu'aucun pupitre n'est
        branché, et elles en ont besoin : ce sont les seules parties du protocole qu'aucune
        spec publique ne décrit."""
        kind = request.args.get("kind") or "source"
        try:
            level = max(1, min(256, int(request.args.get("level") or 1)))
        except (TypeError, ValueError):
            level = 1
        etage = _stage_of(level)
        req = {"cmd": 0, "extended": extended(), "kind": kind,
               "matrix": max(0, matrices()["in"] - 1), "level": level - 1,
               "char_length": label_chars(), "char_index": 0}
        tables, err = model()
        if err:
            return jsonify({"error": err}), 503
        frames, _ = responses_for(req, tables)
        labels = tables.get((etage, "dest" if kind == "dest" else "source")) or {}
        return jsonify({
            "stage": etage, "kind": kind, "level": level,
            "matrix": matrices()["in"], "label_chars": label_chars(),
            "extended": extended(), "labels": len(labels), "frames": len(frames),
            "sample": {"hex": proto.hexstring(frames[0]),
                       "annotated": proto.annotate(frames[0]),
                       "size": len(frames[0])} if frames else None,
            "preview": [{"number": n, "label": labels[n]} for n in sorted(labels)[:40]],
        })

    @bp.route("/api/swp08/apply", methods=["POST"])
    @require_perm("settings.edit")
    def swp08_apply():
        d = request.json or {}
        if "port" in d:
            try:
                p = int(d.get("port") or 0)
            except (TypeError, ValueError):
                return jsonify({"error": "port invalide"}), 400
            if p and not (1 <= p <= 65535):
                return jsonify({"error": "port hors bornes"}), 400
            settings.set("swp08_port", p)
        if "label_chars" in d:
            try:
                c = int(d.get("label_chars"))
            except (TypeError, ValueError):
                return jsonify({"error": "longueur de libellé invalide"}), 400
            if c not in proto.CHAR_LENGTHS:
                return jsonify({"error": "longueur de libellé : %s uniquement"
                                         % ", ".join(map(str, proto.CHAR_LENGTHS))}), 400
            settings.set("swp08_label_chars", c)
        for key, field, lo, hi, lbl in (
                ("swp08_matrix_in", "matrix_in", 1, 256, "matrice d'entrées"),
                ("swp08_matrix_out", "matrix_out", 1, 256, "matrice de sorties"),
                ("swp08_dual_status", "dual_status", 0, 255, "octet d'état du contrôleur"),
                ("swp08_test_matrix", "test_matrix", 1, 16, "matrice du banc d'essai"),
                ("swp08_sdi_per_slot", "sdi_per_slot", 1, 50, "connecteurs SDI par slot"),
                ("swp08_ip_per_slot", "ip_per_slot", 1, 49, "Rx/Tx IP par slot")):
            if field not in d:
                continue
            try:
                v = int(d.get(field))
            except (TypeError, ValueError):
                return jsonify({"error": "%s invalide" % lbl}), 400
            if not (lo <= v <= hi):
                return jsonify({"error": "%s hors bornes (%d–%d)" % (lbl, lo, hi)}), 400
            settings.set(key, v)
        # Les deux matrices PEUVENT être identiques : depuis que la répartition s'indexe sur
        # la MATRICE (le « layer » de VSM, cf. LEVEL_PLAN), ces deux réglages ne servent plus
        # qu'à la route de prévisualisation. Ils ne séparent plus rien.
        for key, field in (("swp08_extended", "extended"),
                           ("swp08_allow_assign", "allow_assign"),
                           ("swp08_push_names", "push_names"),
                           ("swp08_test", "test")):
            if field in d:
                settings.set(key, bool(d.get(field)))
        for key, field in (("swp08_signal_format", "signal_format"),
                           ("swp08_lane_format", "lane_format"),
                           ("swp08_slot_format", "slot_format"),
                           ("swp08_unused_label", "unused_label")):
            if field in d:
                settings.set(key, str(d.get(field) or ""))
        # La taille des grilles et les gabarits changent TOUS les libellés : le modèle en cache
        # doit repartir, sinon le pupitre garderait l'ancien nommage jusqu'à sa péremption.
        if any(f in d for f in ("sdi_per_slot", "ip_per_slot", "signal_format", "lane_format",
                                "slot_format", "unused_label", "label_chars", "test",
                                "test_matrix")):
            threading.Thread(target=notify_change, daemon=True).start()
        if isinstance(d.get("short_names"), dict):
            settings.set("swp08_short_names",
                         {str(k): str(v)[:12] for k, v in d["short_names"].items()})
        enabled = bool(d.get("enabled", settings.get("swp08_enabled")))
        settings.set("swp08_enabled", enabled)
        if enabled and port():
            start(port())
        else:
            stop()
        audit_log("swp08", "apply", "enabled=%s port=%s chars=%d"
                  % (enabled, port(), label_chars()), user_id=None, username=SWP08_ACTOR)
        return jsonify(status_dict())
