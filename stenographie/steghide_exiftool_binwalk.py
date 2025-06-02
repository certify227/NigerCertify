import os
import argparse
from termcolor import cprint

def analyze_exif(file):
    cprint("[*] Analyse des métadonnées (ExifTool)...", "cyan")
    os.system(f"exiftool {file}")

def extract_steghide(file, passphrase):
    cprint("[*] Extraction via Steghide...", "cyan")
    os.system(f"steghide extract -sf {file} -p {passphrase}")

def embed_steghide(file, payload, passphrase):
    cprint("[*] Insertion de données via Steghide...", "cyan")
    os.system(f"steghide embed -cf {file} -ef {payload} -p {passphrase}")

def analyze_binwalk(file):
    cprint("[*] Analyse avec Binwalk...", "cyan")
    os.system(f"binwalk {file}")

def extract_binwalk(file):
    cprint("[*] Extraction avec Binwalk...", "cyan")
    os.system(f"binwalk -e {file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outil avancé de stéganographie")
    parser.add_argument("mode", choices=["exif", "steghide-extract", "steghide-embed", "binwalk", "binwalk-extract"], help="Mode d'analyse")
    parser.add_argument("-f", "--file", help="Fichier cible")
    parser.add_argument("-p", "--payload", help="Fichier à insérer (pour steghide-embed)")
    parser.add_argument("-s", "--secret", help="Mot de passe Steghide")

    args = parser.parse_args()

    if args.mode == "exif":
        analyze_exif(args.file)
    elif args.mode == "steghide-extract":
        extract_steghide(args.file, args.secret)
    elif args.mode == "steghide-embed":
        embed_steghide(args.file, args.payload, args.secret)
    elif args.mode == "binwalk":
        analyze_binwalk(args.file)
    elif args.mode == "binwalk-extract":
        extract_binwalk(args.file)
