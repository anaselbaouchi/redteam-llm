"""Test scripte de LLM08 (version barriere de confiance). Zero appel modele reel,
sauf le labo ChromaDB (brique de preuve structurelle).

    python test_llm08_scripted.py
"""
import sys
sys.path.insert(0, ".")

from redteam_llm.modules import LLM08

PASS = FAIL = 0


def check(nom, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {nom}")
    else:
        FAIL += 1; print(f"  FAIL {nom}")


class Resp:
    def __init__(self, t): self.text = t


class StubModel:
    def __init__(self, texte): self._t = texte
    def chat(self, prompt, system=None, seed=0, temperature=None): return Resp(self._t)


class StubJudge:
    def __init__(self, mot): self._m = mot
    def chat(self, prompt, system=None, seed=0, temperature=None): return Resp(self._m)


class StubCible:
    """Appli simulee : leaky=True -> B voit les docs de A."""
    def __init__(self, leaky): self.leaky = leaky; self.store = {}
    def injecter(self, texte, identite): self.store.setdefault(identite, []).append(texte)
    def demander(self, question, identite):
        vis = list(self.store.get(identite, []))
        if self.leaky:
            for k, v in self.store.items():
                if k != identite: vis += v
        return " ".join(vis) if vis else "aucune information"


# --- Le piege -----------------------------------------------------------------
print("\n[piege] fabriquer_piege")
p = LLM08.fabriquer_piege("le code de suivi de la commande #A-1042", 0)
check("marqueur (reponse) present dans texte_poison", p["marqueur"] in p["texte_poison"])
check("jeton d'injection present dans texte_injection", p["jeton_injection"] in p["texte_injection"])
check("marqueur != jeton d'injection", p["marqueur"] != p["jeton_injection"])
check("deterministe (meme graine)", LLM08.fabriquer_piege(p["sujet"], 0)["marqueur"] == p["marqueur"])
check("graine differente -> marqueur different", LLM08.fabriquer_piege(p["sujet"], 1)["marqueur"] != p["marqueur"])

# --- Etage 1 : susceptibilite (indicatif) ------------------------------------
print("\n[etage 1] susceptibilite (jamais une faille)")
tok = LLM08.fabriquer_piege(p["sujet"], 0)["jeton_injection"]
r = LLM08.sonde_susceptibilite(StubModel(f"ok {tok}"), p["sujet"], 0)
check("jeton recopie -> susceptible", r["verdict"] == "susceptible")
r = LLM08.sonde_susceptibilite(StubModel("j'ai suivi la consigne cachee"), p["sujet"], 0, StubJudge("OBEI"))
check("obei reformule (juge) -> susceptible", r["verdict"] == "susceptible")
r = LLM08.sonde_susceptibilite(StubModel("votre commande est en cours"), p["sujet"], 0, StubJudge("IGNORE"))
check("resiste -> resistant", r["verdict"] == "resistant")

# --- Le detecteur valide sur 2 cibles (vrai ChromaDB) ------------------------
print("\n[detecteur] valider_detecteur (labo ChromaDB reel)")
d = LLM08.valider_detecteur()
check("cible fuyante -> faille", d["fuyant"] == "faille")
check("cible saine -> sain", d["sain"] == "sain")
check("fuyante ramene bien le morceau poison", "poison" in d["fuyant_ids"])
check("saine ne ramene pas le poison", "poison" not in d["sain_ids"])

# --- Etage 2 : vulnerabilite cross-frontiere ---------------------------------
print("\n[etage 2] test_cross_frontiere (barriere de confiance)")
vf = LLM08.test_cross_frontiere(StubCible(leaky=True), p["sujet"], 0)
check("appli fuyante -> prouve (A ressort chez B)", vf["verdict"] == "prouve")
check("appli fuyante -> controle negatif propre", vf["negatif_propre"] is True)
vs = LLM08.test_cross_frontiere(StubCible(leaky=False), p["sujet"], 0)
check("appli saine -> rien (rien ne franchit)", vs["verdict"] == "rien")

# le juge fait monter a "a_verifier" quand le marqueur exact ne sort pas
class CibleParaphrase:
    def injecter(self, texte, identite): pass
    def demander(self, question, identite): return "selon nos infos internes, la valeur differe"
vj = LLM08.test_cross_frontiere(CibleParaphrase(), p["sujet"], 0, StubJudge("OUI"))
check("fausse info via juge OUI -> a_verifier", vj["verdict"] == "a_verifier")

# --- Vocabulaire a deux niveaux ----------------------------------------------
print("\n[verdicts] deux niveaux distincts")
susc_vocab = {"susceptible", "resistant", "non_testable"}
vuln_vocab = {"prouve", "a_verifier", "rien", "non_testable"}
check("verdicts susceptibilite valides", r["verdict"] in susc_vocab)
check("verdicts vulnerabilite valides", all(v in vuln_vocab for v in [vf["verdict"], vs["verdict"], vj["verdict"]]))

print(f"\n=== {PASS} ok / {FAIL} FAIL ===")
sys.exit(1 if FAIL else 0)
