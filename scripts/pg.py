#!/usr/bin/env python3

from datetime import datetime
import json


PG_BADGE_ICON = (
    "iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAf"
    "SC3RAAAABmJLR0QA/wD/AP+gvaeTAAABhUlEQVQo"
    "z32RwUsVURjFf984c7/p5aIQhBQUImxhSc9/wkVg"
    "axFBBZ8LN7nJRf9DSLUIAoWglRAmPEOxPyBm1Ldx"
    "IUIRLty5kHtnXDUtZkbH6dmBC+dyz7nn3O9CBaYd"
    "DQTb0SJAz070qmcnagEE3+KWaUf9Va1Xkt6NeC64"
    "lBOTygJAaIXQSn5hkrWCS/nVuxHP3DD2rccLJmVN"
    "HQ11+YG6fOVcUEfDpHzqW49nAfzBd/uP/6TZKjWo"
    "7c4F3g++3f/um4RlRBp1Y1mzzoG7ZCz76pikC25L"
    "LPDCV8uDW4zef4wP/dAKWRdjaOUecFFWrWoE8NVy"
    "BpVU4bxIuQ+EBa9n/vTU8VWtoBbUCsbxoayqljv5"
    "P/LxWgPq2PKCVFbVkagV1PFjb3P8S26Up6GVRwB7"
    "m+Of1XGUayQxqbzxtnebxybhZejAJKxcv5FhtQxd"
    "DSjhdaFZau82T69KT411Jko+M9IJp0cPs+nRzo25"
    "TY0dPq8O6B/MD3eawEGxfbL2+9lRXfMX0dWGp3g7"
    "yHUAAAAASUVORK5CYII="
)

COMPLETED_BOX_LOOKUP = {
    "FunboxEasy": "2023-11-03",
}

# Read in JSON files
with open("data/pg_boxes.json") as f:
    MACHINES_RETIRED = json.load(f)
with open("data/pg_oscp.json") as f:
    MACHINES_OSCP = json.load(f)


def generate_badges():
    # Determine completed boxes
    completed_box_count = len(COMPLETED_BOX_LOOKUP)

    # Determine OSCP completed
    completed_box_names = list(COMPLETED_BOX_LOOKUP.keys())
    completed_box_count_oscp = [
        box for box in completed_box_names if box in MACHINES_OSCP
    ]
    completed_box_count_oscp = len(completed_box_count_oscp)

    base_url = "https://img.shields.io/badge"

    # Make writeup count badge
    badge_url = (
        f"{base_url}/pg_writeups-{completed_box_count}-green"
        f"?logo=data:image/png;base64,{PG_BADGE_ICON}"
    )
    badge_writeups = f"![htb writeups]({badge_url})"

    # Make oscp-like completed percentage badge
    coverage = round(completed_box_count_oscp / len(MACHINES_OSCP) * 100)
    badge_url = (
        f"{base_url}/htb_writeups-{coverage}%25-green"
        f"?logo=data:image/png;base64,{PG_BADGE_ICON})"
    )
    badge_coverage = f"![htb oscp coverage]({badge_url}"

    return f"{badge_writeups} {badge_coverage}\n"


def generate_toc_table():
    toc_table = ""
    completed_boxes = list([name.lower() for name in COMPLETED_BOX_LOOKUP.keys()])

    # Make machine lookup dict
    machines_retired_lookup = dict()
    for machine in MACHINES_RETIRED:
        machines_retired_lookup[machine["name"].lower()] = machine

    toc_table += (
        "| Name | System | Difficulty | OSCP-like| Release Date | Completed Date |\n"
    )
    toc_table += (
        "| ---- |--------|------------|-------------|--------------|----------------|\n"
    )

    for box_name in completed_boxes:
        box_data = machines_retired_lookup[box_name]
        name = box_data["name"]
        url = f"hackthebox/{name}".lower()
        os = box_data["primary_os"]
        match os:
            case 1:
                os = "Linux"
            case 2:
                os = "Windows"
        difficulty = box_data["difficulty"]
        match difficulty:
            case 1:
                difficulty = "Easy"
            case 2:
                difficulty = "Intermediate"
            case 3:
                difficulty = "Hard"

        release = datetime.strptime(box_data["release_date"], "%Y-%m-%dT%H:%M:%S")
        release = release.strftime("%Y-%m-%d")
        completed = COMPLETED_BOX_LOOKUP[name]

        if name in MACHINES_OSCP:
            oscp_like = "Yes"
        else:
            oscp_like = "No"

        toc_table += f"| [{name}]({url}) | {os} | {difficulty} | {oscp_like} | {release} | {completed} |\n"

    return toc_table
