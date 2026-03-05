import requests
import json
import re
import sys

# Load policy
with open("policy.json") as f:
    policy = json.load(f)

allowed = set(policy["allowed"])
disallowed = set(policy["disallowed"])

violations = []

with open("deps.txt") as f:
    lines = f.readlines()

for line in lines:
    match = re.search(r'(.+):(.+):(.+):(.+)', line)
    if not match:
        continue

    group = match.group(1)
    artifact = match.group(2)
    version = match.group(4)

    url = f"https://search.maven.org/solrsearch/select?q=g:\"{group}\"+AND+a:\"{artifact}\"+AND+v:\"{version}\"&rows=1&wt=json"

    try:
        res = requests.get(url).json()
        docs = res["response"]["docs"]

        if not docs:
            continue

        license_name = docs[0].get("license", "UNKNOWN")

        print(f"{artifact}:{version} -> {license_name}")

        if license_name in disallowed:
            violations.append(f"{artifact}:{version} uses disallowed license {license_name}")

    except Exception as e:
        print("Error fetching license:", e)

if violations:
    print("\nLicense violations detected:\n")

    for v in violations:
        print(v)

    sys.exit(1)

print("\nLicense check passed")
