#!/usr/bin/env python3

from datetime import datetime
import json


HTB_BADGE_ICON = (
    "iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAf"
    "SC3RAAAABmJLR0QA/wD/AP+gvaeTAAABzklEQVQo"
    "z41SPWgTYRh+vu8uLTbkeqiolyFkaRoKEUpKKYWC"
    "ONRmiMUihda0i6ODoFApzg4KCg5udWkMXEUUdGiz"
    "SLp1qKUYh6NZSksJgrH3XZo76CXf6yDVpGnQZ3p5"
    "3+f9f4AOMEVy2BTJ4U5xdtrx3kkZNWk9k/TjJgBw"
    "dvFjkMcXprTVcjOPnxhrR3PdOXtg0WlsWAD3NWW0"
    "X1NG+wHuO40NK2cPLK4dzXW3dMzZfdfr9PM1EPh+"
    "jsfvTfcWvjRXfyuuJT1pvQL8yyo7f/eOXvrMAeCY"
    "ShmJShQgAXjV9o28KkBCohI9plIGANS/MxtLjKmX"
    "XLn1LWtHXgbZ1ScAUKOvj125dZ+zK6ucjCWJstKy"
    "o0R5e17fn+xi8bQkL+XIdcuR65YkL9XF4ul5fX9S"
    "orzddpwTzOrFvKFODALKJqBsGurE4KxezJ/m8bN+"
    "NB7K+gT7gGAfjIey/lmcP4kKwlH8A80cDgABFlsh"
    "uDPLh+GCKYYS7SoaSiwfhgsEdybAYistyvlUvdUj"
    "GsVHdao8UJj2RpIb+a2cnr0GORmVXXjRqySepkMf"
    "3A6SuxGpyZ3nddq9DQAqi74L8tjDKS2/h/+BKUbG"
    "TDEy1in+CwRytDFQHtyiAAAAAElFTkSuQmCC"
)

COMPLETED_BOX_LOOKUP = {
    "Bashed": "2021-06-27",
    "Shocker": "2021-06-27",
    "Lame": "2021-06-27",
    "Nibbles": "2021-07-03",
    "Beep": "2021-07-03",
    "Cronos": "2021-07-04",
    "Nineveh": "2021-07-06",
    "Sense": "2021-07-16",
    "Spectra": "2021-07-21",
    "Legacy": "2021-07-25",
    "Devel": "2021-07-25",
    "Popcorn": "2021-07-26",
    "Armageddon": "2021-07-26",
    "TheNotebook": "2021-07-03",
    "Writeup": "2021-08-04",
    "OpenAdmin": "2021-08-05",
    "Love": "2021-08-14",
    "Tabby": "2021-08-18",
    "Ophiuchi": "2021-08-19",
    "Jerry": "2021-08-20",
    "Knife": "2021-08-30",
    "Blocky": "2021-09-04",
    "Delivery": "2021-09-05",
    "Postman": "2021-09-04",
    "SwagShop": "2021-09-13",
    "Schooled": "2021-09-15",
    "Valentine": "2021-09-17",
    "Irked": "2021-09-20",
    "Blunder": "2021-09-21",
    "Admirer": "2021-09-22",
    "Networked": "2021-09-26",
    "Doctor": "2021-09-28",
    "FriendZone": "2021-09-30",
    "Blue": "2021-10-04",
    "Paper": "2023-10-30",
}

# Read in JSON files
with open("data/htb_boxes.json") as f:
    BOXES_RETIRED = json.load(f)
with open("data/htb_oscp.json") as f:
    BOXES_OSCP = json.load(f)


def generate_badges():
    # Determine completed boxes
    completed_box_count = len(COMPLETED_BOX_LOOKUP)

    # Determine OSCP completed
    completed_box_names = list(COMPLETED_BOX_LOOKUP.keys())
    completed_box_count_oscp = [box for box in completed_box_names if box in BOXES_OSCP]
    completed_box_count_oscp = len(completed_box_count_oscp)

    base_url = "https://img.shields.io/badge"

    # Make writeup count badge
    badge_url = (
        f"{base_url}/htb_writeups-{completed_box_count}-green"
        f"?logo=data:image/png;base64,{HTB_BADGE_ICON}"
    )
    badge_writeups = f"![htb writeups]({badge_url})"

    # Make oscp-like completed percentage badge
    coverage = round(completed_box_count_oscp / len(BOXES_OSCP) * 100)
    badge_url = (
        f"{base_url}/htb_writeups-{coverage}%25-green"
        f"?logo=data:image/png;base64,{HTB_BADGE_ICON})"
    )
    badge_coverage = f"![htb oscp coverage]({badge_url}"

    return f"{badge_writeups} {badge_coverage}\n\n"


def generate_toc_table():
    completed_boxes = list([name.lower() for name in COMPLETED_BOX_LOOKUP.keys()])
    completed_boxes.sort()

    # Make machine lookup dict
    boxes_retired_lookup = dict()
    for machine in BOXES_RETIRED:
        boxes_retired_lookup[machine["name"].lower()] = machine

    toc_table = (
        "| Name | System | Difficulty | OSCP-like| Release Date | Completed Date |\n"
        "| ---- |--------|------------|-------------|--------------|----------------|\n"
    )

    for box_name in completed_boxes:
        box_data = boxes_retired_lookup[box_name]
        name = box_data["name"]
        url = f"hackthebox/{name}".lower()
        os = box_data["os"]
        difficulty = box_data["difficultyText"]
        release = datetime.strptime(box_data["release"], "%Y-%m-%dT%H:%M:%S.%fZ")
        release = release.strftime("%Y-%m-%d")
        completed = COMPLETED_BOX_LOOKUP[name]

        if name in BOXES_OSCP:
            oscp_like = "Yes"
        else:
            oscp_like = "No"

        toc_table += f"| [{name}]({url}) | {os} | {difficulty} | {oscp_like} | {release} | {completed} |\n"

    return toc_table
