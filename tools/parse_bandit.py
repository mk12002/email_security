import json

with open("bandit_results.json") as f:
    res = json.load(f)

for m in res['results']:
    if m['issue_severity'] in ('HIGH', 'MEDIUM') and 'scripts' not in m['filename']:
        print(f"{m['issue_severity']} | {m['test_id']} | {m['filename']}:{m['line_number']} | {m['issue_text']}")
