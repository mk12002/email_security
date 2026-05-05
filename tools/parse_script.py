import json

with open("test_results.json") as f:
    res = json.load(f)

for comp, data in res.items():
    print(f"[{comp}]")
    for case in ("positive", "negative", "edge"):
        out = data[case].get("output", {})
        score = out.get("risk_score", "ERROR")
        inds = out.get("indicators", [])
        print(f"  {case.capitalize()}: Score = {score:4} | Indicators = {inds}")
