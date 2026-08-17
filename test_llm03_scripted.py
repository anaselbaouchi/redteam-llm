"""Test scripte de LLM03 (statique). Zero reseau, zero LLM.

    python test_llm03_scripted.py
"""
import os
import sys
import tempfile
sys.path.insert(0, ".")

from redteam_llm.modules import LLM03

PASS = FAIL = 0


def check(nom, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {nom}")
    else:
        FAIL += 1; print(f"  FAIL {nom}")


def ecrire(dossier, nom, octets):
    chemin = os.path.join(dossier, nom)
    with open(chemin, "wb") as f:
        f.write(octets)
    return chemin


# --- Classement des formats --------------------------------------------------
print("\n[formats] classer_format")
with tempfile.TemporaryDirectory() as d:
    # safetensors (par extension)
    st = ecrire(d, "model.safetensors", b'\x08\x00\x00\x00\x00\x00\x00\x00{"x":1}')
    check("safetensors -> sur", LLM03.classer_format(st)["risque"] == "sur")
    # gguf (par magic bytes)
    gg = ecrire(d, "model.xyz", b"GGUF\x00\x00\x00\x00")
    check("gguf (magic) -> sur", LLM03.classer_format(gg)["risque"] == "sur")
    # pickle brut (magic \x80)
    pk = ecrire(d, "model.bin", b"\x80\x04\x95stuff")
    check("pickle brut (\\x80) -> risque", LLM03.classer_format(pk)["risque"] == "risque")
    # zip/torch (magic PK)
    zp = ecrire(d, "weights.pt", b"PK\x03\x04rest")
    check("zip/torch (PK) -> risque", LLM03.classer_format(zp)["risque"] == "risque")
    # extension a risque MAIS sans magic pickle -> a_verifier, PAS risque (anti faux positif)
    ck = ecrire(d, "x.ckpt", b"random")
    check(".ckpt sans magic -> a_verifier (pas de faux positif)", LLM03.classer_format(ck)["risque"] == "a_verifier")

    # scan d'un dossier
    m = LLM03.scanner_modeles([d])
    check("scan compte les fichiers modele (extensions connues)", m["total"] >= 4)
    check("risque = seulement les pickle confirmes (magic)", m["a_risque"] == 2)
    check("a_verifier = extension sensible non confirmee", m["a_verifier"] >= 1)

# --- La porte d'acces --------------------------------------------------------
print("\n[porte d'acces] run(a_acces=False) -> cadrage")
r = LLM03.run(a_acces=False)
check("pas d'acces -> non_testable", r["verdict"] == "non_testable")
check("pas d'acces -> checklist livree", len(r["checklist"]) >= 5)
check("pas d'acces -> aucun faux scan", "modeles" not in r)

print("\n[porte d'acces] run(a_acces=True) sur un dossier vide")
with tempfile.TemporaryDirectory() as d:
    r2 = LLM03.run(a_acces=True, dossiers_modeles=[d])
    check("acces -> scanne (verdict sain/faille)", r2["verdict"] in ("sain", "faille"))
    check("acces -> section modeles presente", "modeles" in r2)
    check("acces -> section dependances presente", "dependances" in r2)

# --- La checklist ------------------------------------------------------------
print("\n[cadrage] checklist")
check("checklist non vide", len(LLM03.CADRAGE_CHECKLIST) >= 6)
check("checklist parle de safetensors", any("safetensors" in q for q in LLM03.CADRAGE_CHECKLIST))

print(f"\n=== {PASS} ok / {FAIL} FAIL ===")
sys.exit(1 if FAIL else 0)
