#!/usr/bin/env python3
"""
port_scanner.py - Scanner de ports TCP simple et rapide.

Usage:
    python3 port_scanner.py <cible> [--start 1] [--end 1024] [--threads 100] [--timeout 0.5]

Exemples:
    python3 port_scanner.py 192.168.1.1
    python3 port_scanner.py scanme.nmap.org --start 20 --end 100
    python3 port_scanner.py 127.0.0.1 --threads 200 --timeout 0.3

⚠️ Usage légal uniquement : ne scanne que des machines dont tu es
propriétaire ou pour lesquelles tu as une autorisation explicite.
Scanner sans autorisation peut être illégal selon la juridiction.
"""

import argparse
import csv
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Quelques services courants pour donner du contexte au résultat
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}


def grab_banner(target: str, port: int, timeout: float) -> str:
    """Tente de récupérer la bannière du service (les premiers octets envoyés).

    Pour les services qui ne parlent qu'après réception d'une requête (ex: HTTP),
    on envoie une requête minimale pour provoquer une réponse.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            if port in (80, 8080, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(256)
            return banner.decode(errors="replace").strip().replace("\r\n", " | ")
    except (socket.error, UnicodeDecodeError):
        return ""


def scan_port(target: str, port: int, timeout: float, grab: bool) -> tuple[int, bool, str, str]:
    """Tente une connexion TCP sur un port donné. Retourne (port, ouvert, service, bannière)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        is_open = result == 0
    except socket.error:
        is_open = False
    finally:
        sock.close()

    service = COMMON_PORTS.get(port, "")
    banner = grab_banner(target, port, timeout) if (is_open and grab) else ""
    return port, is_open, service, banner


def export_results(results: list[dict], path: str, fmt: str) -> None:
    """Exporte les résultats (liste de dicts) en JSON ou CSV."""
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "service", "banner"])
            writer.writeheader()
            writer.writerows(results)
    print(f"[*] Résultats exportés vers {path} ({fmt.upper()})")


def resolve_target(target: str) -> str:
    """Résout un nom d'hôte en adresse IP, ou lève une erreur claire."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Impossible de résoudre '{target}'. Vérifie le nom/l'IP.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Scanner de ports TCP basique (usage éducatif/autorisé uniquement)."
    )
    parser.add_argument("target", help="Adresse IP ou nom d'hôte à scanner")
    parser.add_argument("--start", type=int, default=1, help="Premier port (défaut: 1)")
    parser.add_argument("--end", type=int, default=1024, help="Dernier port (défaut: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Nombre de threads (défaut: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout par port en secondes (défaut: 0.5)")
    parser.add_argument("--banner", action="store_true", help="Tenter de récupérer la bannière des ports ouverts")
    parser.add_argument("--export", choices=["json", "csv"], help="Exporter les résultats (json ou csv)")
    parser.add_argument("--output", default=None, help="Chemin du fichier d'export (défaut: results.<format>)")
    args = parser.parse_args()

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("[!] Plage de ports invalide (1-65535, start <= end).")
        sys.exit(1)

    ip = resolve_target(args.target)
    print(f"[*] Cible       : {args.target} ({ip})")
    print(f"[*] Plage       : {args.start}-{args.end}")
    print(f"[*] Threads     : {args.threads}")
    print(f"[*] Timeout     : {args.timeout}s")
    print("-" * 45)

    start_time = time.time()
    results = []

    ports = range(args.start, args.end + 1)
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, ip, p, args.timeout, args.banner): p for p in ports
        }
        for future in as_completed(futures):
            port, is_open, service, banner = future.result()
            if is_open:
                label = f" ({service})" if service else ""
                banner_txt = f" — {banner}" if banner else ""
                print(f"[+] Port {port:<6} ouvert{label}{banner_txt}")
                results.append({"port": port, "service": service, "banner": banner})

    elapsed = time.time() - start_time
    results.sort(key=lambda r: r["port"])
    print("-" * 45)
    print(f"[*] Scan terminé en {elapsed:.2f}s — {len(results)} port(s) ouvert(s)")
    if results:
        print(f"[*] Ports ouverts : {[r['port'] for r in results]}")

    if args.export:
        output_path = args.output or f"results.{args.export}"
        export_results(results, output_path, args.export)


if __name__ == "__main__":
    main()
