from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class RunContext:
    client: object
    judge: object
    mode: str
    provider: str
    model: str


def _safe(name: str) -> str:
    return name.replace(":", "_").replace("/", "_")


def _tally_verdicts(obj) -> dict:
    counts = {"PROUVE": 0, "CANDIDAT": 0, "SUSPECT": 0, "SAIN": 0, "NON_TESTABLE": 0}

    def walk(o):
        if isinstance(o, dict):
            v = o.get("verdict_unifie")
            if v in counts:
                counts[v] += 1
            for val in o.values():
                walk(val)
        elif isinstance(o, list):
            for item in o:
                walk(item)

    walk(obj)
    return counts


def resolve_mode(module_id: str, requested_mode: str):
    spec = MODULE_SPECS.get(module_id)
    if spec is None:
        return None, f"module inconnu: {module_id}"
    if requested_mode not in spec["modes"]:
        return None, (f"{module_id} ne supporte pas le mode '{requested_mode}' "
                       f"(modes supportes: {sorted(spec['modes'])})")
    return requested_mode, None


def _run_llm01(ctx: RunContext):
    from redteam_llm.modules import LLM01
    if ctx.mode == "white_box":
        all_findings, negative_control = {}, {}
        for label in ["weak", "hardened", "isolated"]:
            negative_control[label] = LLM01.run_negative_control(ctx.client, label)
        for label in ["weak", "hardened", "isolated"]:
            all_findings[label] = LLM01.run_injection_test(ctx.client, label)
        buff_findings = LLM01.run_buff_comparison(ctx.client)
        path = f"results/llm01/llm01_results_{ctx.provider}_{_safe(ctx.model)}.json"
        LLM01.export_results(all_findings, buff_findings, ctx.client, path,
                             negative_control=negative_control)
        return path, all_findings
    findings = LLM01.run_black_box_test(ctx.client, "external_observed")
    path = f"results/llm01/llm01_extended_results_{ctx.provider}_{_safe(ctx.model)}_external_observed.json"
    LLM01.export_extended_results({}, {"observed": findings}, ctx.client, "external_observed", path)
    return path, {"observed": findings}


def _run_llm02(ctx: RunContext):
    from redteam_llm.modules import LLM02
    if ctx.mode == "black_box":
        boundary = LLM02.run_boundary_test(ctx.client, None, "observed", "black_box", "external_observed")
        baseline = LLM02.run_baseline_test(ctx.client, None, "observed", "black_box", "external_observed")
        all_findings = {"observed": {"boundary": boundary, "baseline": baseline}}
        path = f"results/llm02/llm02_results_{ctx.provider}_{_safe(ctx.model)}_external_observed.json"
        LLM02.export_results(all_findings, ctx.client, "black_box", "external_observed", path)
        return path, all_findings
    collection = LLM02.get_chroma_collection()
    LLM02.run_positive_control(collection)
    all_findings = {}
    for label in ["weak", "hardened", "isolated"]:
        boundary = LLM02.run_boundary_test(ctx.client, collection, label, "white_box", "lab_controlled")
        baseline = LLM02.run_baseline_test(ctx.client, collection, label, "white_box", "lab_controlled")
        all_findings[label] = {"boundary": boundary, "baseline": baseline}
    path = f"results/llm02/llm02_results_{ctx.provider}_{_safe(ctx.model)}_lab_controlled_white_box.json"
    LLM02.export_results(all_findings, ctx.client, "white_box", "lab_controlled", path)
    return path, all_findings


def _run_llm03(ctx: RunContext):
    from redteam_llm.modules import LLM03
    a_acces = ctx.mode == "static"
    res = LLM03.run(a_acces)
    path = "results/llm03/llm03_results.json"
    LLM03.export_results(res, path)
    return path, res


def _run_llm05(ctx: RunContext):
    from redteam_llm.modules import LLM05
    mode = "lab_controlled" if ctx.mode == "white_box" else "external_observed"
    listener = LLM05.OOBListener()
    try:
        findings = LLM05.run_all(ctx.client, mode, listener)
    finally:
        listener.stop()
    path = f"results/llm05/llm05_results_{ctx.provider}_{_safe(ctx.model)}_{mode}.json"
    LLM05.export_results(findings, ctx.client, mode, listener, path)
    return path, findings


def _run_llm06(ctx: RunContext):
    from redteam_llm.modules import LLM06
    mode = "lab_controlled" if ctx.mode == "white_box" else "external_observed"
    findings = LLM06.run_all(ctx.client, mode)
    path = f"results/llm06/llm06_results_{ctx.provider}_{_safe(ctx.model)}_{mode}.json"
    LLM06.export_results(findings, ctx.client, mode, path)
    return path, findings


def _run_llm07(ctx: RunContext):
    from redteam_llm.modules import LLM07
    mode = "lab_controlled" if ctx.mode == "white_box" else "external_observed"
    findings = LLM07.run_all(ctx.client, ctx.judge, mode)
    path = f"results/llm07/llm07_results_{ctx.provider}_{_safe(ctx.model)}_{mode}.json"
    LLM07.export_results(findings, ctx.client, ctx.judge, mode, path)
    return path, findings


def _run_llm08(ctx: RunContext):
    from redteam_llm.modules import LLM08
    if ctx.mode == "black_box":
        return None, {"note": "non_testable"}
    susc = LLM08.run_susceptibilite(ctx.client, ctx.judge)
    detecteur = LLM08.valider_detecteur()
    cross = [
        {"nom": "appli_fuyante",
         **LLM08.test_cross_frontiere(LLM08.CibleLabo(ctx.client, leaky=True), LLM08.SUJETS[0], 0, ctx.judge)},
        {"nom": "appli_saine",
         **LLM08.test_cross_frontiere(LLM08.CibleLabo(ctx.client, leaky=False), LLM08.SUJETS[0], 0, ctx.judge)},
    ]
    path = f"results/llm08/llm08_results_{ctx.provider}_{_safe(ctx.model)}.json"
    LLM08.export_results(susc, detecteur, cross, ctx.client, ctx.judge, path)
    return path, {"susceptibilite": susc, "detecteur": detecteur, "cross_frontiere": cross}


def _run_llm10(ctx: RunContext):
    from redteam_llm.modules import LLM10
    findings = LLM10.run_attack(ctx.client)
    repeat = LLM10.run_repeat_check(ctx.client)
    path = f"results/llm10/llm10_results_{ctx.provider}_{_safe(ctx.model)}.json"
    LLM10.export_results(findings, repeat, path, temperature=ctx.client.temperature)
    return path, {"attack_findings": findings, "repeat_check": repeat}


MODULE_SPECS = {
    "LLM01": {"owasp_id": "LLM01:2025", "modes": {"white_box", "black_box"},
              "needs_client": True, "needs_judge": False, "run": _run_llm01},
    "LLM02": {"owasp_id": "LLM02:2025", "modes": {"white_box", "black_box"},
              "needs_client": True, "needs_judge": False, "run": _run_llm02},
    "LLM03": {"owasp_id": "LLM03:2025", "modes": {"static", "black_box"},
              "needs_client": False, "needs_judge": False, "run": _run_llm03},
    "LLM05": {"owasp_id": "LLM05:2025", "modes": {"white_box", "black_box"},
              "needs_client": True, "needs_judge": False, "run": _run_llm05},
    "LLM06": {"owasp_id": "LLM06:2025", "modes": {"white_box", "black_box"},
              "needs_client": True, "needs_judge": False, "run": _run_llm06},
    "LLM07": {"owasp_id": "LLM07:2025", "modes": {"white_box", "black_box"},
              "needs_client": True, "needs_judge": True, "run": _run_llm07},
    "LLM08": {"owasp_id": "LLM08:2025", "modes": {"white_box", "black_box"},
              "needs_client": True, "needs_judge": True, "run": _run_llm08},
    "LLM10": {"owasp_id": "LLM10:2025", "modes": {"white_box", "black_box"},
              "needs_client": True, "needs_judge": False, "run": _run_llm10},
}


def run_module(module_id: str, ctx: RunContext) -> dict:
    resolved_mode, err = resolve_mode(module_id, ctx.mode)
    if err:
        return {"module": module_id, "owasp_id": MODULE_SPECS[module_id]["owasp_id"],
                "mode": ctx.mode, "status": "skipped", "error": err,
                "raw_results_path": None, "verdict_summary": None}

    spec = MODULE_SPECS[module_id]
    try:
        path, raw_results = spec["run"](ctx)
        return {"module": module_id, "owasp_id": spec["owasp_id"], "mode": ctx.mode,
                "status": "ok", "error": None, "raw_results_path": path,
                "verdict_summary": _tally_verdicts(raw_results)}
    except Exception as e:
        return {"module": module_id, "owasp_id": spec["owasp_id"], "mode": ctx.mode,
                "status": "error", "error": f"{type(e).__name__}: {e}",
                "raw_results_path": None, "verdict_summary": None}
