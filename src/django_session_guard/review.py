"""Read-only review API and bounded value-free report serialization."""
import json
from .contracts import Limits, ReviewError
from .input import read_local, parse_python, parse_json
from .bindings import bind_python, bind_json
from .policy import evaluate

def review_settings(path, *, django_version, input_format="python", limits=None):
    limits = Limits() if limits is None else limits
    if not isinstance(limits, Limits):
        raise TypeError("limits must be Limits or None")
    report = {"schema_version": 1, "tool": "DjangoSessionGuard", "version": "0.1.3",
              "profile": "Django-5.2", "status": "OPEN", "complete": False,
              "findings": [], "runtime_deployment": "OPEN", "cvp_eligibility": "OPEN"}
    try:
        if type(django_version) is not str or django_version != "5.2":
            raise ReviewError("unsupported_django_profile")
        if input_format not in ("python", "json"):
            raise ReviewError("unsupported_input_format")
        source, identity = read_local(path, limits)
        report["input"] = identity
        if input_format == "python":
            tree, starts = parse_python(source, limits)
            values, locations, diagnostics = bind_python(tree, starts, limits)
        else:
            values, locations, diagnostics = bind_json(parse_json(source, limits), limits)
        findings, complete = evaluate(values, locations, diagnostics, limits)
        report["findings"], report["complete"] = findings, complete
        report["status"] = "FAIL" if any(f["status"] == "FAIL" for f in findings) else "PASS" if complete else "OPEN"
    except ReviewError as error:
        report["error"] = {"code": error.code, "location": error.location}
        if error.findings:
            failed = next((item for item in error.findings if item["status"] == "FAIL"), None)
            report["findings"] = [failed] if failed else error.findings[:limits.findings]
            report["status"] = "FAIL" if failed else "OPEN"
    except (RecursionError, MemoryError):
        report["error"] = {"code": "resource_error", "location": None}
    return bound_report(report, limits)

def bound_report(report, limits):
    if len(serialize(report).encode("utf-8")) <= limits.report_bytes:
        return report
    # Preserve a known adverse result even when its detailed ledger cannot fit.
    failed = next((item for item in report["findings"] if item["status"] == "FAIL"), None)
    report["findings"] = [failed] if failed else []
    report["complete"] = False
    report["status"] = "FAIL" if failed else "OPEN"
    report["error"] = {"code": "report_budget", "location": None}
    return report

def serialize(report):
    return json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
