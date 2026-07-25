"""#3 - Mesure du biais de l'auto-juge (re-jugement croise offline).

llama3.2:3b a deja juge les reponses (verdicts sauvegardes dans l'artefact).
Ici on recharge mistral:7b SEUL (sequentiel, aucun conflit VRAM) et on lui fait
re-juger exactement les memes reponses, puis on compare les deux juges.

On isole le juge : on ne garde que les essais ou (a) la detection etait 'judge'
et (b) la reponse n'est PAS un refus evident (is_refusal=False), donc le verdict
llama stocke vient bien du juge et pas du filtre de refus. Comparaison propre
juge-vs-juge, un seul modele charge a la fois.
"""
import json, os, sys
sys.path.insert(0, os.path.abspath("."))

from redteam_llm.modules import LLM01
from redteam_llm.core.llm_client import LLMClient

SRC = "results/llm01/llm01_extended_results_ollama_llama3.2_3b_lab_controlled.json"
JUDGE_MODEL = "mistral:7b"

d = json.load(open(SRC, encoding="utf-8"))
probes = {p["id"]: p for p in LLM01.get_black_box_probes()}
mistral = LLMClient(provider="ollama", model=JUDGE_MODEL, timeout=180)

total = 0
disagree = 0
per_arm = {}

for arm, probelist in d["black_box"].items():
    for f in probelist:
        probe = probes.get(f["id"])
        if probe is None:
            continue
        for det in f.get("details", []):
            if det.get("method") != "judge":
                continue
            llama_complied = det.get("complied")
            resp = det.get("response")
            if llama_complied is None or not resp:
                continue
            # ne garder que les cas reellement juges (pas les refus attrapes par is_refusal)
            if LLM01.is_refusal(resp):
                continue
            v = LLM01.judge_compliance_verdict(mistral, probe["compliance_criterion"], resp)
            if v["verdict"] == "error":
                continue
            mistral_complied = (v["verdict"] == "compliant")
            total += 1
            differ = (mistral_complied != bool(llama_complied))
            disagree += int(differ)
            a = per_arm.setdefault(arm, [0, 0])
            a[0] += int(differ)
            a[1] += 1

print(f"=== #3 biais auto-juge : llama3.2:3b vs mistral:7b ===")
print(f"essais juges compares : {total}")
print(f"desaccords            : {disagree}")
if total:
    print(f"TAUX DE DESACCORD     : {disagree/total*100:.1f}%")
for arm, (dis, tot) in per_arm.items():
    print(f"  {arm}: {dis}/{tot} desaccords")
