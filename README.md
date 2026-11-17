# Scanner de ports TCP en C

![CI](https://github.com/Hamadiy/port-scanner-c/actions/workflows/ci.yml/badge.svg)
![Langage](https://img.shields.io/badge/langage-C11-blue)
![Plateforme](https://img.shields.io/badge/plateforme-Linux-lightgrey)

Un scanner de ports TCP de type *connect scan*, sur le principe de `nmap -sT`. Il ouvre des centaines de connexions non bloquantes en parallèle et les surveille avec `poll()`.

> **Attention :** À utiliser uniquement sur vos propres machines, ou sur un réseau pour lequel vous avez une autorisation écrite.

## Fonctionnalités

- **Scan concurrent** : jusqu'à 1000 connexions simultanées (`connect()` non bloquant + `poll()`), soit environ 1000 ports scannés en 1 s sur un LAN.
- **Trois états par port**, comme nmap :
  - `open` : la poignée de main TCP (SYN, SYN/ACK, ACK) a abouti ;
  - `closed` : l'hôte a répondu par un RST (*connection refused*) ;
  - `filtered` : aucune réponse avant le timeout (paquet probablement bloqué par un pare-feu).
- **Liste de ports souple** : `22,80,443`, `1-1024`, `20-25,8000-8100`. Les doublons sont fusionnés.
- **Nom du service** déduit de `/etc/services` (`ssh`, `http`, …).
- Résolution DNS de la cible.

## Compilation

```bash
make
make test
```

## Utilisation

```bash
./bin/portscan [-p ports] [-t timeout_ms] [-c concurrency] [-a] <host>
```

```
$ ./bin/portscan -p 20-25,80,443,3306 192.168.1.10
Scanning 192.168.1.10 (192.168.1.10): 9 port(s), timeout 1000 ms

PORT     STATE     SERVICE
22       open      ssh
80       open      http
3306     open      mysql

Done in 1.00 s: 3 open, 6 closed, 0 filtered
```

| Option | Rôle | Défaut |
|---|---|---|
| `-p` | ports à scanner | `1-1024` |
| `-t` | timeout de connexion (ms) | `1000` |
| `-c` | connexions simultanées | `200` |
| `-a` | afficher aussi les ports fermés ou filtrés | – |

## Fonctionnement

1. Pour chaque port d'un lot, un socket est passé en `O_NONBLOCK`, puis `connect()` est appelé. L'appel retourne immédiatement avec `EINPROGRESS`.
2. `poll()` attend que les sockets deviennent inscriptibles (`POLLOUT`), donc que la connexion soit terminée, avec un délai maximal commun au lot.
3. `getsockopt(SO_ERROR)` donne le résultat de chaque connexion : `0` → open, `ECONNREFUSED` → closed.
4. Les sockets encore en attente à l'échéance sont marqués `filtered`.

## Tests

`tests/run_tests.sh` lance un serveur HTTP local, puis vérifie :
- que son port est détecté `open` et qu'un port voisin est détecté `closed` ;
- que le résumé final est correct ;
- que les spécifications de ports invalides sont rejetées.

## Auteur

**Younesse HAMADI** – étudiant en BUT Réseaux & Télécommunications.
