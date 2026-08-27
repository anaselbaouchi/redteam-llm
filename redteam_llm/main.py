"""
python -m redteam_llm.main --target ollama:llama3.2:3b --mode white_box --modules all
"""
import argparse
import json
import os
from datetime import datetime

from redteam_llm.core.llm_client import LLMClient
from redteam_llm.core.registry import MODULE_SPECS, RunContext, run_module


def parse_target(target: str):
    if target == "static":
        return None, None
    if ":" not in target:
        raise ValueError(f"cible invalide: '{target}' (attendu: provider:model, ou 'static')")
    provider, model = target.split(":", 1)
    return provider, model


def build_clients(provider, model, base_url, api_key, judge_provider, judge_model, needs_client, needs_judge):
    client = None
    judge = None
    if needs_client:
        client = LLMClient(provider=provider, model=model, base_url=base_url, api_key=api_key,
                           timeout=300, temperature=0.7)
    if needs_judge:
        jp = judge_provider or provider
        jm = judge_model or model
        judge = LLMClient(provider=jp, model=jm, timeout=180, temperature=0.0)
    return client, judge


def main():
    ap = argparse.ArgumentParser(description="Lanceur unique redteam-llm")
    ap.add_argument("--target", required=True, help="provider:model (ex: ollama:llama3.2:3b) ou 'static'")
    ap.add_argument("--mode", required=True, choices=["white_box", "black_box", "static"])
    ap.add_argument("--modules", default="all", help="'all' ou liste separee par virgules (ex: LLM01,LLM07)")
    ap.add_argument("--base-url", default=os.getenv("BASE_URL"))
    ap.add_argument("--api-key", default=os.getenv("API_KEY"))
    ap.add_argument("--judge-provider", default=os.getenv("JUDGE_PROVIDER"))
    ap.add_argument("--judge-model", default=os.getenv("JUDGE_MODEL"))
    args = ap.parse_args()

    provider, model = parse_target(args.target)
    module_ids = list(MODULE_SPECS.keys()) if args.modules == "all" else args.modules.split(",")

    unknown = [m for m in module_ids if m not in MODULE_SPECS]
    if unknown:
        print(f"module(s) inconnu(s), ignore(s): {unknown}")
        module_ids = [m for m in module_ids if m in MODULE_SPECS]

    needs_client = any(MODULE_SPECS[m]["needs_client"] for m in module_ids)
    needs_judge = any(MODULE_SPECS[m]["needs_judge"] for m in module_ids)

    if needs_client and provider is None:
        besoin = [m for m in module_ids if MODULE_SPECS[m]["needs_client"]]
        print(f"cible 'static' invalide : {besoin} ont besoin d'une vraie cible "
              f"(--target provider:model, ex: ollama:llama3.2:3b)")
        return

    client, judge = build_clients(provider, model, args.base_url, args.api_key,
                                   args.judge_provider, args.judge_model,
                                   needs_client, needs_judge)

    if client is not None and not client.is_alive():
        print("cible injoignable, arret")
        return

    ctx = RunContext(client=client, judge=judge, mode=args.mode,
                     provider=provider or "static", model=model or "static")

    print(f"\n(lanceur | cible: {args.target} | mode: {args.mode} | modules: {module_ids})")

    results = []
    for module_id in module_ids:
        print(f"\n=== {module_id} ===")
        envelope = run_module(module_id, ctx)
        print(f"  statut: {envelope['status']}"
              + (f" ({envelope['error']})" if envelope["error"] else ""))
        if envelope["verdict_summary"]:
            print(f"  verdicts: {envelope['verdict_summary']}")
        results.append(envelope)

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_dir = f"results/run_{run_id}"
    os.makedirs(summary_dir, exist_ok=True)
    summary_path = f"{summary_dir}/summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({"run_id": run_id, "target": args.target, "mode": args.mode,
                   "modules": results}, f, indent=2, ensure_ascii=False)

    print(f"\nresume consolide: {summary_path}")


if __name__ == "__main__":
    main()
