#!/usr/bin/env python3
"""
Generate FedRAMP 20x KSI compliance framework files for Prowler.

Fetches the FedRAMP Machine-Readable (FRMR) documentation and generates
Low and Moderate baseline framework JSON files for AWS, Azure, and GCP.

Existing Prowler check mappings are carried forward from the feature branch
files using the FRMR's fka (formerly-known-as) ID mapping.

Usage:
    python3 scripts/generate_fedramp_20x_ksi.py
"""

import json
import subprocess
import sys
import urllib.request
from pathlib import Path

FRMR_URL = "https://raw.githubusercontent.com/FedRAMP/docs/main/FRMR.documentation.json"
REPO_ROOT = Path(__file__).resolve().parent.parent
COMPLIANCE_DIR = REPO_ROOT / "prowler" / "compliance"
PROVIDERS = ["aws", "azure", "gcp"]
BASELINES = ["low", "moderate"]

# Source branch for existing check mappings (old numbered ID format)
SOURCE_BRANCH = "feature/fedramp-20x-ksi-low-update-v25.11C"

# Theme display names (from FRMR)
THEME_NAMES = {
    "KSI-AFR": "Authorization by FedRAMP",
    "KSI-CMT": "Change Management",
    "KSI-CNA": "Cloud Native Architecture",
    "KSI-CED": "Cybersecurity Education",
    "KSI-IAM": "Identity and Access Management",
    "KSI-INR": "Incident Response",
    "KSI-MLA": "Monitoring, Logging, and Auditing",
    "KSI-PIY": "Policy and Inventory",
    "KSI-RPL": "Recovery Planning",
    "KSI-SVC": "Service Configuration",
    "KSI-SCR": "Supply Chain Risk",
}

# Theme ordering for output (short keys as used in FRMR JSON)
THEME_ORDER = [
    "AFR",
    "CED",
    "CMT",
    "CNA",
    "IAM",
    "INR",
    "MLA",
    "PIY",
    "RPL",
    "SVC",
    "SCR",
]


def fetch_frmr(local_path=None):
    """Fetch FRMR documentation from GitHub or a local file."""
    if local_path:
        print(f"Reading FRMR from {local_path}...")
        with open(local_path, encoding="utf-8") as f:
            return json.load(f)

    print(f"Fetching FRMR from {FRMR_URL}...")
    try:
        with urllib.request.urlopen(FRMR_URL) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        # Fallback: try curl
        print(f"  urllib failed ({e}), trying curl...")
        result = subprocess.run(
            ["curl", "-sL", FRMR_URL],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)


def load_existing_checks(provider):
    """Load existing check mappings from the feature branch using git show."""
    path = f"prowler/compliance/{provider}/fedramp_20x_ksi_low_{provider}.json"
    try:
        result = subprocess.run(
            ["git", "show", f"{SOURCE_BRANCH}:{path}"],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO_ROOT,
        )
        data = json.loads(result.stdout)
        # Build mapping: old_id -> {checks, assessment_status, automation_source}
        mapping = {}
        for req in data["Requirements"]:
            mapping[req["Id"]] = {
                "checks": req["Checks"],
                "assessment_status": req["Attributes"][0]["AssessmentStatus"],
                "automation_source": req["Attributes"][0]["AutomationSource"],
            }
        return mapping
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"  Warning: Could not read existing checks for {provider}")
        return {}


def extract_ksi_indicators(frmr):
    """Extract all KSI indicators from the FRMR, organized by theme."""
    ksi_section = frmr["KSI"]
    indicators = []

    for theme_short in THEME_ORDER:
        theme_data = ksi_section.get(theme_short)
        if not theme_data:
            print(f"  Warning: Theme {theme_short} not found in FRMR")
            continue

        # The full theme ID is in the "id" field (e.g., "KSI-AFR")
        theme_id = theme_data.get("id", f"KSI-{theme_short}")
        theme_name = theme_data.get("name", THEME_NAMES.get(theme_id, theme_id))
        indicator_map = theme_data.get("indicators", {})

        for indicator_key, indicator_data in sorted(indicator_map.items()):
            # Get statement - may be top-level or in varies_by_level
            statement = indicator_data.get("statement", "")
            varies_by_level = indicator_data.get("varies_by_level")
            name = indicator_data.get("name", indicator_key)
            fka = indicator_data.get("fka", "")
            controls = indicator_data.get("controls", [])

            indicators.append(
                {
                    "theme_id": theme_id,
                    "theme_name": theme_name,
                    "indicator_key": indicator_key,  # e.g., "KSI-IAM-MFA"
                    "name": name,
                    "statement": statement,
                    "varies_by_level": varies_by_level,
                    "fka": fka,
                    "controls": controls,
                }
            )

    return indicators


def build_fka_mapping(indicators):
    """Build mapping from old numbered IDs to new abbreviated IDs."""
    fka_to_new = {}
    for ind in indicators:
        fka = ind["fka"]
        if fka:
            # fka is like "KSI-AFR-01" -> normalize to lowercase "ksi-afr-01"
            fka_lower = fka.lower()
            fka_to_new[fka_lower] = ind["indicator_key"].lower()
    return fka_to_new


def get_description(indicator, baseline):
    """Get the appropriate description for an indicator at a given baseline."""
    varies = indicator["varies_by_level"]
    if varies:
        level_data = varies.get(baseline, {})
        statement = level_data.get("statement", indicator["statement"])
        # Clean up markdown bold from "**Optional:**"
        if statement:
            statement = statement.replace("**Optional:**", "Optional:").replace(
                "**Optional: **", "Optional: "
            )
        return statement
    return indicator["statement"]


def generate_framework(indicators, provider, baseline, existing_checks, fka_mapping):
    """Generate a single framework JSON structure."""
    framework_name = f"FedRAMP-20x-KSI-{baseline.capitalize()}"
    baseline_label = baseline.capitalize()
    frmr_version = "FRMR-0.9.42"

    requirements = []

    for ind in indicators:
        indicator_id = ind["indicator_key"].lower()  # e.g., "ksi-afr-mas"
        indicator_key_upper = ind["indicator_key"]  # e.g., "KSI-AFR-MAS"
        section = f"{ind['theme_id']}: {ind['theme_name']}"
        subsection = f"{indicator_key_upper}: {ind['name']}"
        description = get_description(ind, baseline)

        # Look up existing checks using fka mapping
        fka_lower = ind["fka"].lower() if ind["fka"] else ""
        existing = existing_checks.get(fka_lower, {})
        checks = existing.get("checks", [])
        assessment_status = existing.get("assessment_status", "Manual")
        automation_source = existing.get("automation_source", None)

        # If no checks, ensure Manual status
        if not checks:
            assessment_status = "Manual"
            automation_source = None

        requirement = {
            "Id": indicator_id,
            "Name": f"{indicator_key_upper}: {ind['name']}",
            "Description": description if description else f"{ind['name']}.",
            "Attributes": [
                {
                    "ItemId": indicator_id,
                    "Section": section,
                    "SubSection": subsection,
                    "Service": provider,
                    "AssessmentStatus": assessment_status,
                    "AutomationSource": automation_source,
                }
            ],
            "Checks": checks,
        }
        requirements.append(requirement)

    framework = {
        "Framework": framework_name,
        "Name": f"FedRAMP 20x Key Security Indicators (KSIs) - {baseline_label} Impact Level {frmr_version}",
        "Version": frmr_version,
        "Provider": provider.upper(),
        "Description": (
            f"FedRAMP 20x Key Security Indicators (KSIs) {baseline_label} Impact Level "
            f"represent core security indicators for cloud service providers, focusing on "
            f"automation, continuous monitoring, and cloud-native security principles per "
            f"FedRAMP 20x requirements for {baseline_label} impact systems. "
            f"Generated from the FedRAMP Machine-Readable Documentation (FRMR) version 0.9.42-beta."
        ),
        "Requirements": requirements,
    }

    return framework


def write_framework(framework, provider, baseline):
    """Write a framework JSON file."""
    output_dir = COMPLIANCE_DIR / provider
    output_path = output_dir / f"fedramp_20x_ksi_{baseline}_{provider}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(framework, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return output_path


def main():
    # Fetch FRMR (accept optional local path as first argument)
    local_path = sys.argv[1] if len(sys.argv) > 1 else None
    frmr = fetch_frmr(local_path)
    version = frmr["info"]["version"]
    last_updated = frmr["info"]["last_updated"]
    print(f"FRMR version: {version}, last updated: {last_updated}")

    # Extract KSI indicators
    indicators = extract_ksi_indicators(frmr)
    print(f"Extracted {len(indicators)} KSI indicators across {len(THEME_ORDER)} themes")

    # Show varies_by_level indicators
    varies = [i for i in indicators if i["varies_by_level"]]
    if varies:
        print(f"\nIndicators with varies_by_level ({len(varies)}):")
        for v in varies:
            print(f"  {v['indicator_key']}: {v['name']}")

    # Build fka mapping
    fka_mapping = build_fka_mapping(indicators)
    print(f"\nfka mappings: {len(fka_mapping)} old->new ID mappings")

    # Generate frameworks for each provider and baseline
    for provider in PROVIDERS:
        print(f"\n--- {provider.upper()} ---")
        existing_checks = load_existing_checks(provider)
        print(f"  Loaded {len(existing_checks)} existing check mappings")

        # Show which old IDs successfully mapped
        mapped = 0
        unmapped_old = []
        for old_id, new_id in sorted(fka_mapping.items()):
            if old_id in existing_checks:
                mapped += 1
            else:
                unmapped_old.append(old_id)
        print(f"  Successfully mapped {mapped} old IDs to new IDs")

        for baseline in BASELINES:
            framework = generate_framework(
                indicators, provider, baseline, existing_checks, fka_mapping
            )
            output_path = write_framework(framework, provider, baseline)
            req_count = len(framework["Requirements"])
            auto_count = sum(
                1
                for r in framework["Requirements"]
                if r["Attributes"][0]["AssessmentStatus"] == "Automated"
            )
            print(
                f"  {baseline.capitalize()}: {req_count} indicators "
                f"({auto_count} automated, {req_count - auto_count} manual) "
                f"-> {output_path.relative_to(REPO_ROOT)}"
            )

    print("\nDone!")


if __name__ == "__main__":
    main()
