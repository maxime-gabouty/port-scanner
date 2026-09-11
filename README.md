# Port Scanner

Un scanner de ports TCP simple en Python, multithreadé, avec identification
des services courants (SSH, HTTP, MySQL, etc.).

## Fonctionnalités
- Scan multithreadé pour aller vite sur de larges plages de ports
- Résolution automatique nom d'hôte → IP
- Reconnaissance des services courants sur les ports bien connus
- Banner grabbing (récupération de la bannière des services sur les ports ouverts)
- Export des résultats en JSON ou CSV
- Timeout et nombre de threads configurables

## Installation
Aucune dépendance externe — seulement la bibliothèque standard Python 3.

```bash
git clone <url-du-repo>
cd port-scanner
```

## Usage

```bash
python3 port_scanner.py <cible> [--start 1] [--end 1024] [--threads 100] [--timeout 0.5]
```

### Exemples
```bash
# Scan des 1024 premiers ports d'une machine locale
python3 port_scanner.py 192.168.1.1

# Scan d'une plage spécifique
python3 port_scanner.py scanme.nmap.org --start 20 --end 100

# Scan rapide avec plus de threads
python3 port_scanner.py 127.0.0.1 --threads 200 --timeout 0.3

# Scan avec récupération des bannières
python3 port_scanner.py 192.168.1.1 --banner

# Scan avec export des résultats en JSON
python3 port_scanner.py 192.168.1.1 --export json --output scan_results.json

# Scan avec export en CSV
python3 port_scanner.py 192.168.1.1 --export csv
```

### Options disponibles
| Option | Description | Défaut |
|---|---|---|
| `--start` | Premier port | 1 |
| `--end` | Dernier port | 1024 |
| `--threads` | Nombre de threads | 100 |
| `--timeout` | Timeout par port (secondes) | 0.5 |
| `--banner` | Active le banner grabbing | désactivé |
| `--export` | Format d'export (`json` ou `csv`) | aucun |
| `--output` | Chemin du fichier d'export | `results.<format>` |

## Exemple de sortie
```
[*] Cible       : 127.0.0.1 (127.0.0.1)
[*] Plage       : 1-1024
[*] Threads     : 100
[*] Timeout     : 0.5s
---------------------------------------------
[+] Port 22     ouvert (SSH)
[+] Port 80     ouvert (HTTP)
---------------------------------------------
[*] Scan terminé en 1.34s — 2 port(s) ouvert(s)
[*] Ports ouverts : [22, 80]
```

## ⚠️ Avertissement légal
Cet outil est fourni à des fins **éducatives**. Ne scanne que des machines
dont tu es propriétaire ou pour lesquelles tu as une **autorisation explicite**.
Le scan de ports sans autorisation peut constituer une infraction pénale
selon la juridiction (en France : article 323-1 du Code pénal).

## Pistes d'amélioration
- Ajout d'un mode UDP
- Export des résultats en JSON/CSV
- Bannière grabbing (récupération de la version du service)
- Scan en parallèle sur plusieurs cibles (fichier de liste d'IP)

## Licence
MIT
