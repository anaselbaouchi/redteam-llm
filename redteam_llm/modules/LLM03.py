"""LLM03 - Supply Chain Vulnerabilities.

Module STATIQUE (pas de LLM, pas de marqueur, pas de juge) : on inspecte les artefacts
au repos (dependances, fichiers de modele, hash), pas le comportement.

Regle de perimetre (porte d'acces) :
  - Sans acces aux artefacts (ex : banque, chat seulement) -> NON TESTABLE. On ne fabrique
    aucun scan : on rend une FICHE DE CADRAGE (checklist a remplir en interne).
  - Avec acces (ex : notre labo, nos propres fichiers) -> scan statique reel.

Ce qui est teste (avec acces) :
  - dependances Python (pip-audit si dispo, sinon inventaire) -> CVE connues.
  - fichiers de modele : format sur (safetensors/gguf/onnx) vs a risque (pickle : bin/pt/pkl...).
  - empreintes (sha256) pour verification de provenance.
"""
import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime
from importlib import metadata


# --- La fiche de cadrage (livree quand pas d'acces) --------------------------

CADRAGE_CHECKLIST = [
    "Un inventaire des composants (SBOM) est-il genere et tenu a jour ?",
    "Les modeles sont-ils au format safetensors (pas de pickle executable) ?",
    "Les dependances sont-elles scannees en continu (pip-audit / Snyk / Dependabot) ?",
    "La provenance des modeles et adaptateurs (LoRA) est-elle verifiee (hash / signature) ?",
    "Les modeles proviennent-ils de sources fiables (pas de depot non verifie) ?",
    "Existe-t-il une liste blanche des plugins / outils autorises ?",
    "Les fichiers de modele sont-ils scannes (picklescan / ModelScan) avant chargement ?",
    "Le risque des modeles tiers a-t-il ete revu (licence, provenance des donnees, backdoor) ?",
]


# --- Classement des formats de fichier de modele -----------------------------

FORMATS_SURS = {".safetensors": "safetensors", ".gguf": "gguf", ".onnx": "onnx"}
FORMATS_RISQUE = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".h5", ".pb"}


def classer_format(chemin: str) -> dict:
    ext = os.path.splitext(chemin)[1].lower()
    try:
        with open(chemin, "rb") as f:
            tete = f.read(8)
    except Exception as e:
        return {"format": "illisible", "risque": "a_verifier", "raison": str(e)}

    if tete[:4] == b"GGUF":
        return {"format": "gguf", "risque": "sur", "raison": "format binaire sans code"}
    if ext in FORMATS_SURS:
        return {"format": FORMATS_SURS[ext], "risque": "sur", "raison": "format sans execution de code"}
    # RISQUE confirme seulement si les octets de tete prouvent un pickle / une archive torch.
    if tete[:1] == b"\x80":
        return {"format": "pickle", "risque": "risque", "raison": "pickle brut : execution de code au chargement"}
    if tete[:2] == b"PK" and ext in FORMATS_RISQUE:
        return {"format": "zip/torch", "risque": "risque", "raison": "archive torch contenant du pickle"}
    # extension a risque mais format NON confirme (ex : .bin d'index ChromaDB) -> a verifier, PAS une faille
    if ext in FORMATS_RISQUE:
        return {"format": ext.lstrip("."), "risque": "a_verifier",
                "raison": "extension sensible mais pickle non confirme (verifier a la main)"}
    return {"format": "inconnu", "risque": "a_verifier", "raison": "extension non reconnue"}


def sha256(chemin: str, limite_mo: int = 500) -> str:
    try:
        if os.path.getsize(chemin) > limite_mo * 1024 * 1024:
            return "trop_gros"
        h = hashlib.sha256()
        with open(chemin, "rb") as f:
            for bloc in iter(lambda: f.read(1 << 20), b""):
                h.update(bloc)
        return h.hexdigest()[:16]
    except Exception:
        return "erreur"


EXT_MODELE = set(FORMATS_SURS) | FORMATS_RISQUE
TAILLE_BLOB_MIN = 5 * 1024 * 1024   # un vrai poids de modele fait au moins quelques Mo


def _est_candidat(chemin: str, nom: str) -> bool:
    ext = os.path.splitext(nom)[1].lower()
    if ext in EXT_MODELE or nom.lower() == "pytorch_model.bin":
        return True
    # blobs sans extension (ex : Ollama sha256-...) : on regarde s'ils sont gros ET binaires
    if ext == "" or nom.startswith("sha256-"):
        try:
            if os.path.getsize(chemin) >= TAILLE_BLOB_MIN:
                with open(chemin, "rb") as f:
                    tete = f.read(4)
                return tete in (b"GGUF",) or tete[:1] == b"\x80" or tete[:2] == b"PK"
        except Exception:
            return False
    return False


def scanner_modeles(dossiers: list) -> dict:
    fichiers = []
    for base in dossiers:
        if not base or not os.path.isdir(base):
            continue
        for racine, _, noms in os.walk(base):
            for nom in noms:
                chemin = os.path.join(racine, nom)
                if _est_candidat(chemin, nom):
                    info = classer_format(chemin)
                    fichiers.append({"fichier": os.path.relpath(chemin, base), "base": base,
                                     "sha256": sha256(chemin), **info})
    n_risque = sum(1 for f in fichiers if f["risque"] == "risque")
    n_verifier = sum(1 for f in fichiers if f["risque"] == "a_verifier")
    return {"total": len(fichiers), "a_risque": n_risque, "a_verifier": n_verifier, "fichiers": fichiers}


# --- Dependances : pip-audit si dispo, sinon inventaire ----------------------

def scanner_dependances() -> dict:
    try:
        out = subprocess.run([sys.executable, "-m", "pip_audit", "--format", "json"],
                             capture_output=True, text=True, timeout=180)
        if out.stdout.strip():
            data = json.loads(out.stdout)
            deps = data.get("dependencies", data if isinstance(data, list) else [])
            vulns = [{"paquet": d.get("name"), "version": d.get("version"),
                      "ids": [v.get("id") for v in d.get("vulns", [])]}
                     for d in deps if d.get("vulns")]
            return {"outil": "pip-audit", "vulnerables": len(vulns), "details": vulns}
    except FileNotFoundError:
        pass
    except Exception as e:
        return {"outil": "pip-audit (erreur)", "note": str(e)[:120]}

    paquets = sorted({(d.metadata["Name"], d.version) for d in metadata.distributions()
                      if d.metadata.get("Name")})
    return {"outil": "aucun", "paquets_installes": len(paquets),
            "note": "installer pip-audit pour detecter les CVE : pip install pip-audit"}


# --- Detection auto des artefacts locaux (notre labo) ------------------------

def artefacts_locaux() -> list:
    home = os.path.expanduser("~")
    candidats = [
        os.path.join(home, ".ollama", "models"),      # modeles Ollama (GGUF)
        os.path.join(home, ".cache", "huggingface"),  # cache HuggingFace (peut contenir du pickle)
        os.path.join(os.getcwd(), "lab"),
    ]
    return [c for c in candidats if os.path.isdir(c)]


# --- Orchestration : la porte d'acces ----------------------------------------

def run(a_acces: bool, dossiers_modeles: list = None) -> dict:
    if not a_acces:
        return {
            "verdict": "non_testable",
            "raison": "pas d'acces aux artefacts (chat seulement) - hors perimetre boite noire",
            "livrable": "fiche de cadrage",
            "checklist": CADRAGE_CHECKLIST,
        }
    dossiers = dossiers_modeles or artefacts_locaux()
    deps = scanner_dependances()
    modeles = scanner_modeles(dossiers)
    faille = deps.get("vulnerables", 0) > 0 or modeles["a_risque"] > 0
    return {
        "verdict": "faille" if faille else "sain",
        "dossiers_scannes": dossiers,
        "dependances": deps,
        "modeles": modeles,
        "checklist": CADRAGE_CHECKLIST,
    }


def print_resume(res: dict) -> None:
    print("\n--- LLM03 (Supply Chain) ---")
    if res["verdict"] == "non_testable":
        print("  NON TESTABLE (pas d'acces) -> fiche de cadrage livree :")
        for q in res["checklist"]:
            print(f"    [ ] {q}")
        return
    d = res["dependances"]
    print(f"  dependances  : outil={d['outil']}  "
          f"{'vulnerables=' + str(d.get('vulnerables')) if 'vulnerables' in d else 'paquets=' + str(d.get('paquets_installes'))}")
    m = res["modeles"]
    print(f"  modeles      : {m['total']} fichiers, {m['a_risque']} a risque (pickle confirme), "
          f"{m.get('a_verifier', 0)} a verifier")
    for f in m["fichiers"]:
        if f["risque"] == "risque":
            print(f"     [!] {f['fichier']}  ({f['format']} : {f['raison']})")
    for f in m["fichiers"]:
        if f["risque"] == "a_verifier":
            print(f"     [?] {f['fichier']}  ({f['raison']})")
    print(f"  >>> verdict : {res['verdict']}")


def export_results(res: dict, filepath: str) -> None:
    payload = {
        "module": "LLM03_supply_chain",
        "owasp_category": "LLM03:2025 Supply Chain",
        "timestamp": datetime.now().isoformat(),
        "type": "statique (artefacts au repos, pas de comportement)",
        **res,
    }
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"\nresults exported to {filepath}")


if __name__ == "__main__":
    # porte d'acces : LLM03_SCOPE=blackbox -> pas d'acces (cadrage) ; sinon labo (scan reel)
    scope = os.getenv("LLM03_SCOPE", "lab")
    a_acces = scope != "blackbox"
    chemin = os.getenv("LLM03_MODEL_PATH")
    dossiers = [chemin] if chemin else None

    print(f"\n(LLM03 | scope: {scope} | acces artefacts: {a_acces})")
    res = run(a_acces, dossiers)
    print_resume(res)
    export_results(res, "results/llm03/llm03_results.json")
