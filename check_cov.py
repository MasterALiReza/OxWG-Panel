import json
import glob
import re

rules = json.load(open('tests/rules_183.json'))
covered_eps = set()
for fpath in glob.glob('blueprints/*_bp.py'):
    text = open(fpath, encoding='utf-8').read()
    for m in re.finditer(r'def\s+(\w+)\s*\(', text):
        covered_eps.add(m.group(1))

uncovered = [r for r in rules if r['endpoint'] not in covered_eps]
print(f'Total rules: {len(rules)}, Uncovered: {len(uncovered)}')
for r in uncovered:
    print(f"{r['rule']:45} -> {r['endpoint']:30} {r['methods']}")
