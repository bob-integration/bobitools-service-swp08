# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Protocole SW-P-08 (Pro-Bel « General Switcher Communication Protocol ») — couche filaire.

Module PUR : aucune socket, aucun réglage, aucun accès au parc. Il ne fait que traduire entre
des octets et des structures Python, ce qui le rend testable intégralement hors réseau — c'est
la méthode qui a mis au point le service TSL, et elle vaut ici davantage encore puisqu'on ne
peut rien vérifier tant qu'un contrôleur ne nous parle pas.

── Sources de cette implémentation ─────────────────────────────────────────────────────
1. Pro-Bel/Snell SW-P-88 « Router Control Protocols », Issue 4b (2016) : le FRAMING et la poignée
   de main, repris mot pour mot ci-dessous. C'est la seule partie dont on a la spec.
2. Le module Companion `generic-swp08` (open source, en service) : les NUMÉROS DE COMMANDE
   et la disposition des messages de noms, absents de l'Issue 1 (ils sont arrivés en Issue 4).
   Une implémentation qui tourne vaut mieux qu'un souvenir, mais ce n'est pas la norme :
   tout ce qui vient de là est signalé, et reste à confronter au banc.

── Trame ───────────────────────────────────────────────────────────────────────────────
    SOM      DATA      BTC      CHK      EOM

    SOM = DLE STX (0x10 0x02)          BTC = nombre d'octets de DATA
    EOM = DLE ETX (0x10 0x03)          CHK = complément à 2 sur 8 bits de (DATA + BTC)

Tout octet DLE présent dans DATA, BTC ou CHK est DOUBLÉ avant l'ajout du SOM/EOM — sans quoi
un 0x10 dans une charge utile se lirait comme un début de trame. Le doublage se fait donc APRÈS
le calcul de la somme, et le dédoublage AVANT sa vérification : c'est la faute classique sur ce
protocole, et elle ne se voit qu'avec des libellés qui contiennent le bon octet.

DATA est plafonné à **128 octets** (garanti par la spec pour tous les systèmes ; 255 permis en
applicatif propriétaire). Les listes de noms sont donc DÉCOUPÉES en plusieurs messages, chacun
annonçant son rang de départ et son nombre de libellés.

── Poignée de main ─────────────────────────────────────────────────────────────────────
Après émission, l'émetteur attend un ACK. Un NAK signale un défaut de packaging (format, BTC,
somme) ; la spec recommande 5 tentatives. Un ACK/NAK peut apparaître ENTRE deux trames, y
compris au milieu d'un flux — `unpack` les rend donc comme des événements à part entière.

── Libellés ────────────────────────────────────────────────────────────────────────────
Trois longueurs seulement : 4, 8 ou 12 caractères, désignées par un INDEX (0, 1, 2) et non par
leur valeur. Un libellé plus court est complété par des espaces ; un libellé plus long est
tronqué — il n'y a pas de troisième voie, et c'est la contrainte la plus dure du protocole.
"""

DLE = 0x10
STX = 0x02
ETX = 0x03
ACK = 0x06
NAK = 0x15

# Un acquittement part PRÉFIXÉ D'UN DLE : `10 06`, pas `06` nu (exemples de l'Issue 4b §10).
# C'est ce préfixe qui autorise la spec à dire qu'un ACK peut s'intercaler au milieu d'un flux
# « sans confusion avec les DLE embarqués » : puisque tout DLE de charge utile est doublé, la
# séquence `10 06` ne peut pas apparaître ailleurs. Un `06` nu est accepté en entrée par
# tolérance, mais jamais émis.
FRAME_ACK = bytes([DLE, ACK])
FRAME_NAK = bytes([DLE, NAK])

MAX_DATA = 128                 # garanti par la spec ; 255 possible mais non portable
CHAR_LENGTHS = (4, 8, 12)      # index 0, 1, 2 — le fil transporte l'INDEX, pas la longueur

# ─── Commandes (numéros repris du module Companion `generic-swp08`) ─────────
# Jeu STANDARD : matrice et niveau tiennent dans UN octet (4 bits chacun), donc 16 matrices,
# 16 niveaux, et des numéros de signal sur 16 bits.
CMD_GET_SOURCE_NAMES = 0x64
CMD_GET_SINGLE_SOURCE_NAME = 0x65
CMD_GET_DEST_NAMES = 0x66
CMD_GET_SINGLE_DEST_NAME = 0x67
CMD_GET_UMD_LABELS = 0x68
CMD_GET_SINGLE_UMD_LABEL = 0x69
CMD_SOURCE_NAMES_RESPONSE = 0x6A
CMD_DEST_NAMES_RESPONSE = 0x6B
CMD_UMD_LABELS_RESPONSE = 0x6C
CMD_NAMES_UPDATED = 0x1E       # « relis mes noms » — poussé après une réaffectation

# Jeu ÉTENDU : matrice et niveau ont chacun leur octet (256 niveaux), signaux sur 16 bits.
CMD_EXT_GET_SOURCE_NAMES = 0xE4
CMD_EXT_GET_SINGLE_SOURCE_NAME = 0xE5
CMD_EXT_GET_DEST_NAMES = 0xE6
CMD_EXT_GET_SINGLE_DEST_NAME = 0xE7
CMD_EXT_GET_UMD_LABELS = 0xE8
CMD_EXT_GET_SINGLE_UMD_LABEL = 0xE9
CMD_EXT_SOURCE_NAMES_RESPONSE = 0xEA
CMD_EXT_DEST_NAMES_RESPONSE = 0xEB

CMD_NAMES = {
    CMD_GET_SOURCE_NAMES: "noms de sources",
    CMD_GET_DEST_NAMES: "noms de destinations",
    CMD_GET_UMD_LABELS: "libellés UMD",
    CMD_EXT_GET_SOURCE_NAMES: "noms de sources (étendu)",
    CMD_EXT_GET_DEST_NAMES: "noms de destinations (étendu)",
    CMD_EXT_GET_UMD_LABELS: "libellés UMD (étendu)",
    CMD_SOURCE_NAMES_RESPONSE: "réponse noms de sources",
    CMD_DEST_NAMES_RESPONSE: "réponse noms de destinations",
    CMD_UMD_LABELS_RESPONSE: "réponse libellés UMD",
    CMD_EXT_SOURCE_NAMES_RESPONSE: "réponse noms de sources (étendu)",
    CMD_EXT_DEST_NAMES_RESPONSE: "réponse noms de destinations (étendu)",
    CMD_NAMES_UPDATED: "noms modifiés",
    0x01: "interrogate", 0x02: "connect", 0x03: "tally", 0x04: "connected",
    0x08: "état contrôleur (demande)", 0x09: "état contrôleur (réponse)",
    0x15: "demande de dump", 0x16: "dump (octet)", 0x17: "dump (mot)",
}


# ═════════════════════════════════════════════════════════════════════
# Framing
# ═════════════════════════════════════════════════════════════════════

def checksum(payload):
    """Complément à 2 sur 8 bits de la somme des octets. `payload` = DATA + BTC."""
    return (-sum(payload)) & 0xFF


def _escape(raw):
    """Double chaque DLE. À n'appliquer QU'APRÈS le calcul de la somme."""
    out = bytearray()
    for b in raw:
        out.append(b)
        if b == DLE:
            out.append(DLE)
    return bytes(out)


def pack(data):
    """DATA applicatif → trame complète, prête à partir."""
    data = bytes(data)
    if not data:
        raise ValueError("DATA vide")
    if len(data) > 255:
        raise ValueError("DATA de %d octets : le compteur BTC tient sur un octet" % len(data))
    btc = len(data) & 0xFF
    chk = checksum(data + bytes([btc]))
    return bytes([DLE, STX]) + _escape(data + bytes([btc, chk])) + bytes([DLE, ETX])


def unpack(buf):
    """(événements, reste) depuis un flux d'octets reçus.

    Chaque événement est `("ack", None)`, `("nak", None)`, `("message", data)` ou
    `("erreur", raison)`. Le `reste` est ce qui n'a pas encore de fin de trame : l'appelant le
    reconserve et rappelle avec la suite — un message peut arriver en plusieurs paquets TCP, et
    supposer le contraire est la deuxième faute classique de ce protocole.

    Une trame mal formée est signalée SANS interrompre l'analyse du reste : un octet perdu sur
    une liaison ne doit pas condamner tout ce qui suit."""
    events = []
    i, n = 0, len(buf)
    consumed = 0
    while i < n:
        b = buf[i]
        if b == ACK:
            events.append(("ack", None))
            i += 1
            consumed = i
            continue
        if b == NAK:
            events.append(("nak", None))
            i += 1
            consumed = i
            continue
        if b != DLE:
            i += 1                      # octet hors trame : ignoré en silence
            consumed = i
            continue
        if i + 1 >= n:
            break                       # DLE en fin de tampon : on attend la suite
        if buf[i + 1] == ACK:
            events.append(("ack", None))
            i += 2
            consumed = i
            continue
        if buf[i + 1] == NAK:
            events.append(("nak", None))
            i += 2
            consumed = i
            continue
        if buf[i + 1] != STX:
            i += 2                      # DLE isolé hors trame
            consumed = i
            continue
        # Début de trame : on cherche le DLE ETX de fin, en sautant les DLE DLE.
        j = i + 2
        raw = bytearray()
        end = -1
        while j < n:
            if buf[j] == DLE:
                if j + 1 >= n:
                    break               # doublage ou fin coupés : on attend
                if buf[j + 1] == DLE:
                    raw.append(DLE)
                    j += 2
                    continue
                if buf[j + 1] == ETX:
                    end = j + 2
                    break
                j += 2                  # DLE suivi d'autre chose : hors norme, on saute
                continue
            raw.append(buf[j])
            j += 1
        if end < 0:
            break                       # trame incomplète : on garde tout à partir de i
        i = end
        consumed = i
        if len(raw) < 3:
            events.append(("erreur", "trame trop courte (%d octets)" % len(raw)))
            continue
        data, btc, chk = bytes(raw[:-2]), raw[-2], raw[-1]
        if btc != (len(data) & 0xFF):
            events.append(("erreur", "BTC annoncé %d, reçu %d" % (btc, len(data))))
            continue
        if checksum(data + bytes([btc])) != chk:
            events.append(("erreur", "somme de contrôle invalide"))
            continue
        events.append(("message", data))
    return events, buf[consumed:]


# ═════════════════════════════════════════════════════════════════════
# Requêtes reçues du contrôleur
# ═════════════════════════════════════════════════════════════════════

def decode_request(data):
    """Décode une demande de noms, ou None si la commande n'en est pas une.

    Dispositions (module Companion) — noter l'asymétrie, qui n'est pas une coquille :
      standard  : cmd, (matrice << 4) | niveau, index de longueur
      étendu    : cmd, matrice, niveau, index de longueur     ← sources et UMD
                  cmd, matrice, index de longueur             ← destinations, SANS niveau

    Une DESTINATION n'a pas de niveau : elle est la même sur tous les niveaux, ce sont les
    sources qui se déclinent par niveau. C'est exactement le modèle du breakaway."""
    if not data:
        return None
    cmd = data[0]
    ext = cmd in (CMD_EXT_GET_SOURCE_NAMES, CMD_EXT_GET_DEST_NAMES, CMD_EXT_GET_UMD_LABELS)
    std = cmd in (CMD_GET_SOURCE_NAMES, CMD_GET_DEST_NAMES, CMD_GET_UMD_LABELS)
    if not (ext or std):
        return None
    is_dest = cmd in (CMD_GET_DEST_NAMES, CMD_EXT_GET_DEST_NAMES)
    try:
        if std:
            matrix, level = (data[1] & 0xF0) >> 4, data[1] & 0x0F
            ci = data[2]
        elif is_dest:
            matrix, level, ci = data[1], 0, data[2]
        else:
            matrix, level, ci = data[1], data[2], data[3]
    except IndexError:
        return None
    if ci >= len(CHAR_LENGTHS):
        return None
    kind = ("dest" if is_dest else
            "umd" if cmd in (CMD_GET_UMD_LABELS, CMD_EXT_GET_UMD_LABELS) else "source")
    return {"cmd": cmd, "extended": ext, "kind": kind,
            "matrix": matrix, "level": level, "char_length": CHAR_LENGTHS[ci], "char_index": ci}


# ═════════════════════════════════════════════════════════════════════
# Réponses émises vers le contrôleur
# ═════════════════════════════════════════════════════════════════════

def _fit(label, width):
    """Ajuste un libellé à la largeur EXACTE du protocole.

    Encodage latin-1 avec repli : le protocole est d'avant l'UTF-8 et compte en OCTETS, donc
    « Pélicase » doit peser 8 et non 9. Un caractère hors jeu devient « ? » plutôt que de
    décaler tout le message — un libellé approximatif se lit, un message décalé ne se lit pas."""
    txt = str(label or "")
    raw = txt.encode("latin-1", "replace")
    return raw[:width].ljust(width, b" ")


def _response_cmd(kind, extended):
    if kind == "dest":
        return CMD_EXT_DEST_NAMES_RESPONSE if extended else CMD_DEST_NAMES_RESPONSE
    if kind == "umd":
        return CMD_UMD_LABELS_RESPONSE
    return CMD_EXT_SOURCE_NAMES_RESPONSE if extended else CMD_SOURCE_NAMES_RESPONSE


def name_responses(kind, labels, *, matrix=0, level=0, char_length=12, extended=False,
                   first=1, max_data=MAX_DATA):
    """Liste de DATA (à passer à `pack`) répondant à une demande de noms.

    `labels` = {numéro affiché: libellé}. Les numéros ABSENTS ne sont pas comblés : on
    n'émet que des tranches contiguës de ce qui existe, plutôt qu'un vivier plein de vides.
    C'est le contraire du choix fait côté Ember+ (grille pleine, §12.7) et c'est délibéré —
    ici le nombre de messages est proportionnel à ce qu'on émet, alors qu'un arbre Ember+ se
    parcourt une fois.

    Le champ « rang » du protocole est le numéro du libellé PRÉCÉDANT le premier de la
    tranche : le récepteur calcule `id = rang + position + 1`. Un décalage d'une unité ici
    renomme tout le routeur, d'où `first`, qui dit à quel numéro affiché correspond l'id 1."""
    if char_length not in CHAR_LENGTHS:
        raise ValueError("longueur de libellé %r hors protocole %r" % (char_length, CHAR_LENGTHS))
    ci = CHAR_LENGTHS.index(char_length)
    cmd = _response_cmd(kind, extended)
    head = ([cmd, matrix, ci] if (extended and kind == "dest") else
            [cmd, matrix, level, ci] if extended else
            [cmd, ((matrix & 0x0F) << 4) | (level & 0x0F), ci])
    head_len = len(head) + 3            # + rang (2 octets) + compte (1 octet)
    per_msg = max(1, (max_data - head_len) // char_length)
    if not labels:
        return []
    # Tranches CONTIGUËS : on coupe dès qu'un numéro manque, sinon le rang annoncé mentirait.
    runs, cur = [], []
    for num in sorted(labels):
        if cur and num != cur[-1] + 1:
            runs.append(cur)
            cur = []
        cur.append(num)
    runs.append(cur)
    out = []
    for run in runs:
        for pos in range(0, len(run), per_msg):
            chunk = run[pos:pos + per_msg]
            rank = chunk[0] - first          # id = rang + position + 1
            if rank < 0:
                continue
            body = bytearray(head)
            body += bytes([(rank >> 8) & 0xFF, rank & 0xFF, len(chunk)])
            for num in chunk:
                body += _fit(labels[num], char_length)
            out.append(bytes(body))
    return out


# ═════════════════════════════════════════════════════════════════════
# Commandes de routage (état seulement — on ne commute pas par ce canal)
# ═════════════════════════════════════════════════════════════════════

CMD_INTERROGATE = 0x01
CMD_CONNECT = 0x02
CMD_TALLY = 0x03
CMD_CONNECTED = 0x04
CMD_DUAL_STATUS_REQ = 0x08
CMD_DUAL_STATUS_RESP = 0x09
CMD_TALLY_DUMP_REQ = 0x15          # 21 décimal
CMD_TALLY_DUMP_BYTE = 0x16         # 22 — destinations et sources <= 191
CMD_TALLY_DUMP_WORD = 0x17         # 23 — jusqu'à 65535, 64 tallies par message

TALLY_DUMP_MAX = 64                # plafond annoncé par la spec (§8.2.4)


def _mx(matrix, level):
    """Octet matrice/niveau : matrice en bits 4-7, niveau en bits 0-3 (§8.1.1)."""
    return ((matrix & 0x0F) << 4) | (level & 0x0F)


def decode_routing(data):
    """Décode une commande d'état ou de routage, ou None. Tout est en BASE 0 sur le fil.

    Le « multiplicateur » du §8.1.1 est un reliquat des liaisons série 7 bits : la destination
    et la source se lisent sur 128, et les bits de poids fort voyagent séparément. On le
    reconstitue ici pour ne plus jamais y penser ailleurs."""
    if not data:
        return None
    cmd = data[0]
    try:
        if cmd == CMD_DUAL_STATUS_REQ:
            return {"cmd": cmd, "kind": "dual_status"}
        if cmd == CMD_TALLY_DUMP_REQ:
            return {"cmd": cmd, "kind": "tally_dump",
                    "matrix": (data[1] & 0xF0) >> 4, "level": data[1] & 0x0F}
        if cmd in (CMD_INTERROGATE, CMD_CONNECT):
            matrix, level = (data[1] & 0xF0) >> 4, data[1] & 0x0F
            mult = data[2]
            dest = ((mult & 0x70) >> 4) * 128 + data[3]
            src = None
            if cmd == CMD_CONNECT:
                src = (mult & 0x07) * 128 + data[4]
            return {"cmd": cmd, "kind": "connect" if cmd == CMD_CONNECT else "interrogate",
                    "matrix": matrix, "level": level, "dest": dest, "source": src}
    except IndexError:
        return None
    return None


def dual_status(status_byte=0x02):
    """DATA de la réponse d'état du contrôleur (09).

    ⚠ La spec dit seulement « *Bit 1 of byte 1 of the response is then used to indicate whether
    the controller is active or idle* » — sans donner la valeur qui vaut « actif », ni si le
    bit est compté depuis 0. On arme donc le bit d'index 1 (0x02) par défaut, et l'octet est
    RÉGLABLE : si le pupitre nous croit inactif, c'est le premier bouton à tourner."""
    return bytes([CMD_DUAL_STATUS_RESP, status_byte & 0xFF])


STD_SIGNAL_MAX = 1023      # multiplicateur sur 3 bits + reste sur 7 : 7×128 + 127


def tally(matrix, level, dest, source, *, connected=False):
    """DATA d'un tally (03) ou d'un connected (04) — même disposition, seule la commande change.

    Le choix n'est PAS cosmétique : le `03` répond à un interrogate, le `04` confirme un
    connect (§8.2.1 et §8.2.2). Répondre l'un pour l'autre laisse le pupitre sans réponse —
    constaté au banc le 2026-07-30, où un `03` renvoyé à un connect n'a produit aucun effet.

    ⚠ **Lève au-delà de 1023.** Le multiplicateur du §8.1.1 tient sur 3 bits, donc ces commandes
    ne savent adresser que 1024 signaux. Or le plan de numérotation monte à 1699 pour seize
    slots : un numéro plus grand serait REPLIÉ en silence — un croisement du slot 13 annoncé sur
    le slot 5, ce qui est pire qu'une absence. On refuse donc franchement, à charge de
    l'appelant de sauter ou de passer aux commandes étendues (129 à 132), que le pupitre
    déclare supporter et qui restent à implémenter."""
    for nom, v in (("destination", dest), ("source", source)):
        if not (0 <= v <= STD_SIGNAL_MAX):
            raise ValueError("%s %d hors de portée des commandes standard (max %d)"
                             % (nom, v, STD_SIGNAL_MAX))
    return bytes([CMD_CONNECTED if connected else CMD_TALLY, _mx(matrix, level),
                  ((dest // 128) & 0x07) << 4 | ((source // 128) & 0x07),
                  dest % 128, source % 128])


def tally_dump_word(matrix, level, first_dest, sources):
    """DATA d'un dump (23), format WORD : une destination de départ puis N sources
    CONSÉCUTIVES. Jusqu'à 64 par message (§8.2.4), d'où le découpage par l'appelant."""
    body = bytearray([CMD_TALLY_DUMP_WORD, _mx(matrix, level), len(sources),
                      (first_dest >> 8) & 0xFF, first_dest & 0xFF])
    for s in sources:
        body += bytes([(s >> 8) & 0xFF, s & 0xFF])
    return bytes(body)


def decode_name_response(data):
    """Décode une réponse de noms REÇUE, ou None si ce n'en est pas une.

    Le sens du flux surprend, et c'est le constat du banc : le pupitre visé ne DEMANDE jamais
    les noms d'un routeur, il POUSSE les siens (160 trames `6A` et 160 `6B` reçues le
    2026-07-30 sans qu'aucune requête soit partie). L'autorité de nommage est donc chez lui.
    Savoir lire ce qu'il envoie vaut mieux que l'ignorer : c'est la seule façon de comparer son
    plan de nommage au nôtre, et éventuellement de l'adopter.

    Disposition — la même que celle qu'on ÉMET, lue à l'envers (cf. `name_responses`)."""
    if not data:
        return None
    cmd = data[0]
    ext = cmd in (CMD_EXT_SOURCE_NAMES_RESPONSE, CMD_EXT_DEST_NAMES_RESPONSE)
    std = cmd in (CMD_SOURCE_NAMES_RESPONSE, CMD_DEST_NAMES_RESPONSE, CMD_UMD_LABELS_RESPONSE)
    if not (ext or std):
        return None
    is_dest = cmd in (CMD_DEST_NAMES_RESPONSE, CMD_EXT_DEST_NAMES_RESPONSE)
    try:
        i = 1
        if ext:
            matrix, i = data[i], i + 1
            level = 0
            if not is_dest:                      # une destination n'a pas de niveau
                level, i = data[i], i + 1
        else:
            matrix, level, i = (data[i] & 0xF0) >> 4, data[i] & 0x0F, i + 1
        ci, i = data[i], i + 1
        if ci >= len(CHAR_LENGTHS):
            return None
        width = CHAR_LENGTHS[ci]
        rank = (data[i] << 8) | data[i + 1]
        i += 2
        count, i = data[i], i + 1
    except IndexError:
        return None
    labels = {}
    for k in range(count):
        chunk = data[i + k * width:i + (k + 1) * width]
        if len(chunk) < width:
            break
        labels[rank + k + 1] = chunk.decode("latin-1", "replace").rstrip("\x00 ").strip()
    kind = ("dest" if is_dest else
            "umd" if cmd == CMD_UMD_LABELS_RESPONSE else "source")
    return {"cmd": cmd, "extended": ext, "kind": kind, "matrix": matrix, "level": level,
            "char_length": width, "labels": labels}


def names_updated(matrix=0):
    """DATA du message « mes noms ont changé, relis-les ».

    ⚠ **VSM ne l'implémente pas** (sa table donne `SWP08_NamesUpdated (30)` comme « not
    implemented »). L'émettre est donc sans effet sur ce pupitre : après une réaffectation de
    slot, il gardera les anciens noms jusqu'à ce qu'il relise de lui-même. Conservé parce que
    c'est le mécanisme prévu par le protocole et qu'un autre contrôleur peut l'honorer — mais
    ne pas compter dessus pour la mise à jour du parc."""
    return bytes([CMD_NAMES_UPDATED, matrix])


# ═════════════════════════════════════════════════════════════════════
# Mise au point hors réseau
# ═════════════════════════════════════════════════════════════════════

def hexstring(frame):
    return " ".join("%02X" % b for b in frame)


def annotate(frame):
    """Rend une trame en hexadécimal COMMENTÉ, champ par champ. C'est l'outil qui permet de
    tout vérifier avant qu'un contrôleur existe — le service TSL a été mis au point comme ça."""
    if len(frame) < 6:
        return "trame trop courte : " + hexstring(frame)
    lines = ["%s  SOM (DLE STX)" % hexstring(frame[:2])]
    events, _ = unpack(frame)
    data = next((d for k, d in events if k == "message"), None)
    if data is None:
        raison = next((d for k, d in events if k == "erreur"), "illisible")
        return "\n".join(lines + ["%s  ← %s" % (hexstring(frame[2:]), raison)])
    cmd = data[0]
    lines.append("%02X  commande — %s" % (cmd, CMD_NAMES.get(cmd, "inconnue")))
    resp = cmd in (CMD_SOURCE_NAMES_RESPONSE, CMD_DEST_NAMES_RESPONSE, CMD_UMD_LABELS_RESPONSE,
                   CMD_EXT_SOURCE_NAMES_RESPONSE, CMD_EXT_DEST_NAMES_RESPONSE)
    if resp:
        ext = cmd in (CMD_EXT_SOURCE_NAMES_RESPONSE, CMD_EXT_DEST_NAMES_RESPONSE)
        i = 1
        if ext:
            lines.append("%02X  matrice %d" % (data[i], data[i])); i += 1
            if cmd != CMD_EXT_DEST_NAMES_RESPONSE:
                lines.append("%02X  niveau %d" % (data[i], data[i])); i += 1
        else:
            lines.append("%02X  matrice %d, niveau %d"
                         % (data[i], (data[i] & 0xF0) >> 4, data[i] & 0x0F)); i += 1
        width = CHAR_LENGTHS[data[i]] if data[i] < len(CHAR_LENGTHS) else 0
        lines.append("%02X  longueur de libellé : index %d → %d caractères" % (data[i], data[i], width)); i += 1
        rank = (data[i] << 8) | data[i + 1]
        lines.append("%02X %02X  rang %d (le premier libellé porte l'id %d)"
                     % (data[i], data[i + 1], rank, rank + 1)); i += 2
        count = data[i]
        lines.append("%02X  %d libellé(s) dans ce message" % (count, count)); i += 1
        for k in range(count):
            chunk = data[i + k * width:i + (k + 1) * width]
            lines.append("%-*s  id %d = %r"
                         % (width * 3, hexstring(chunk), rank + k + 1,
                            chunk.decode("latin-1").rstrip()))
    else:
        lines.append("%s  charge utile" % hexstring(data[1:]))
    lines.append("%02X  BTC (%d octets de DATA)" % (len(data), len(data)))
    lines.append("%02X  CHK" % checksum(data + bytes([len(data) & 0xFF])))
    lines.append("%s  EOM (DLE ETX)" % hexstring(frame[-2:]))
    return "\n".join(lines)
