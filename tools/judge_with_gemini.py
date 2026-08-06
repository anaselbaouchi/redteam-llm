
import os
import sys
import json
import time

sys.path.insert(0, ".")
from redteam_llm.core.llm_client import LLMClient
from redteam_llm.modules import LLM06


def confusion(pairs):
    tp = fp = tn = fn = 0
    for g, e in pairs:
        if g and e: tp += 1
        elif g and not e: fn += 1
        elif not g and e: fp += 1
        else: tn += 1
    n = tp + fp + tn + fn
    acc = (tp + tn) / n * 100 if n else 0
    pre = tp / (tp + fp) * 100 if (tp + fp) else 0
    rec = tp / (tp + fn) * 100 if (tp + fn) else 0
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, n=n, acc=acc, pre=pre, rec=rec)


def show(label, c):
    print(f"{label}")
    print(f"   accord avec la verite : {c['acc']:.0f}%   ({c['tp']+c['tn']}/{c['n']})")
    print(f"   precision : {c['pre']:.0f}%    rappel : {c['rec']:.0f}%    "
          f"(FP={c['fp']} FN={c['fn']})")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        print("usage: python -m tools.judge_with_gemini <fichier_resultats.json>")
        return

    provider = os.getenv("JUDGE_PROVIDER", "groq")
    model = os.getenv("JUDGE_MODEL", "llama-3.3-70b-versatile")
    sleep = float(os.getenv("JUDGE_SLEEP", "4"))
    limit = int(os.getenv("LIMIT", "0"))

    judge = LLMClient(provider=provider, model=model, temperature=0.0, timeout=60,
                      max_retries=int(os.getenv("JUDGE_RETRIES", "6")))
    print(f"juge externe : {provider} / {model}\n")

    d = json.load(open(path, encoding="utf-8"))
    probes = {p["id"]: p for p in LLM06.PROBES}

    local_pairs, gem_pairs, head = [], [], []
    done = 0
    errors = 0
    for x in d["results"]:
        probe = probes[x["id"]]
        for det in x["details"]:
            wb = det.get("white_box")
            if not wb or wb.get("vulnerable") is None:
                continue
            g = bool(wb["vulnerable"])
            local_v = det["black_box"].get("vulnerable")

            res = LLM06.check_agency_black_box(det["final_response"], probe,
                                               client=judge, use_judge=True)
            gem_v = res["vulnerable"]
            if res.get("judge_error"):
                errors += 1
                if errors == 1:
                    print(f"!! erreur du juge externe: {res['judge_error'][:120]}\n")
            if sleep:
                time.sleep(sleep)

            if local_v is not None:
                local_pairs.append((g, bool(local_v)))
            if gem_v is not None:
                gem_pairs.append((g, bool(gem_v)))
            if local_v is not None and gem_v is not None:
                head.append((bool(local_v), bool(gem_v)))

            done += 1
            if limit and done >= limit:
                break
        if limit and done >= limit:
            break

    print(f"essais notes : {done}   (erreurs juge externe: {errors})\n")
    show("JUGE LOCAL (llama3.2:3b)", confusion(local_pairs))
    print()
    show(f"JUGE EXTERNE ({model})", confusion(gem_pairs))
    print()
    same = sum(1 for a, b in head if a == b)
    print(f"les deux juges d'accord entre eux : {same}/{len(head)} "
          f"({same/len(head)*100:.0f}%)" if head else "n/a")


if __name__ == "__main__":
    main()
