"""Test scripte du moteur de capacites (les 5 etapes). Zero appel modele reel.

    python test_capability_scan_scripted.py
"""
import sys
sys.path.insert(0, ".")

from redteam_llm.core import capability_scan as cs

PASS = FAIL = 0


def check(nom, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {nom}")
    else:
        FAIL += 1; print(f"  FAIL {nom}")


class Resp:
    def __init__(self, t): self.text = t


class StubJudge:
    """Renvoie un mapping fixe (DANS/HORS) quel que soit le prompt."""
    def __init__(self, texte): self._t = texte
    def chat(self, prompt, system=None, temperature=0.0, seed=0): return Resp(self._t)


class StubOOB:
    """Serveur OOB simule : on controle si un callback est 'recu'."""
    def __init__(self, recu=False, host="oob.test"): self._recu = recu; self.public_host = host
    def url_for(self, token): return f"http://{self.public_host}/ping/{token}"
    def got(self, token): return self._recu


class StubCible:
    """Appli simulee : renvoie ce qu'on lui a injecte (echo)."""
    def __init__(self, canaux_sup): self._c = set(canaux_sup); self.store = {}
    def canaux(self): return self._c
    def injecter(self, texte, canal, identite):
        if canal in self._c:
            self.store.setdefault(identite, []).append(texte)
    def demander(self, question, identite="user"):
        return " ".join(self.store.get(identite, [])) or "aucune info"


class CibleMuette:
    """Ne stocke rien, ne renvoie rien d'utile (pour tester 'rien')."""
    def canaux(self): return {"upload"}
    def injecter(self, texte, canal, identite): pass
    def demander(self, question, identite="user"): return "je ne peux pas repondre"


# --- Etape 1 : juge mappe le texte libre vers la taxonomie -------------------
print("\n[etape 1] juge_mapper")
j = StubJudge("DANS: upload_document, recuperation_web\nHORS: generation d'images")
m = cs.juge_mapper(j, "je lis vos fichiers et je vais sur le web et je fais des images")
check("mappe vers les cles de la taxonomie", set(m["revendiquees"]) == {"upload_document", "recuperation_web"})
check("capacite hors taxonomie captee", any("image" in h.lower() for h in m["hors_taxonomie"]))
check("ne garde que les cles valides", all(c in cs.TAXONOMIE for c in m["revendiquees"]))

# --- Etape 2 : sonde de confirmation (marqueur) ------------------------------
print("\n[etape 2] sonde_confirmation")
conf_ok = cs.sonde_confirmation(StubCible({"upload"}), "upload_document")
check("canal supporte + marqueur ressort -> confirmee", conf_ok["confirmee"] is True)
conf_na = cs.sonde_confirmation(StubCible({"upload"}), "recuperation_web")
check("canal absent -> non_testable", conf_na["statut"] == "non_testable")

# --- Etape 3 : test d'attaque avec porte d'impact OOB ------------------------
print("\n[etape 3] test_attaque (porte d'impact)")
# callback recu -> prouve
a_prouve = cs.test_attaque(StubCible({"upload"}), "upload_document", StubOOB(recu=True))
check("callback OOB recu -> prouve", a_prouve["verdict"] == "prouve")
# pas de callback mais l'URL malveillante ressort (echo) -> susceptible
a_susc = cs.test_attaque(StubCible({"upload"}), "upload_document", StubOOB(recu=False))
check("URL produite sans callback -> susceptible", a_susc["verdict"] == "susceptible")
# rien ne ressort + juge IGNORE -> rien
a_rien = cs.test_attaque(CibleMuette(), "upload_document", StubOOB(recu=False), judge=StubJudge("IGNORE"))
check("injection non suivie -> rien", a_rien["verdict"] == "rien")

# --- Etape 4 : hors taxonomie -> surface a verifier --------------------------
print("\n[etape 4] surface_a_verifier")
sv = cs.surface_a_verifier(["generation d'images", "acces agenda"])
check("chaque capacite hors taxo -> une entree", len(sv) == 2)
check("chaque entree = verification manuelle", all(e["action"] == "verification manuelle" for e in sv))

# --- Etape 5 : scanner complet (bout en bout) --------------------------------
print("\n[etape 5] scanner (les 5 etapes enchainees)")
cible = StubCible({"upload"})
judge = StubJudge("DANS: upload_document, outils_actions\nHORS: generation d'images")
res = cs.scanner(cible, judge)
carte = {e["capacite"]: e for e in res["carte"]}
check("upload confirme (canal present)", carte["upload_document"]["statut"] == "confirmee")
check("upload a une attaque", "attaque" in carte["upload_document"])
check("outils_actions faussement revendique -> non_testable (FP ecarte)",
      carte["outils_actions"]["statut"] == "non_testable")
check("capacites sans canal -> non_testable", carte["recuperation_web"]["statut"] == "non_testable")
check("hors taxonomie remonte", len(res["surface_a_verifier"]) >= 1)

print(f"\n=== {PASS} ok / {FAIL} FAIL ===")
sys.exit(1 if FAIL else 0)
