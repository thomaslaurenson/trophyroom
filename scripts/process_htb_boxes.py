import json

all_boxes = list()

with open("data/htb_raw_active.json") as f:
    data = json.load(f)

for box in data:
    # Clean the box to minimal properties
    box_mod = dict()
    box_mod["name"] = box["name"]
    box_mod["os"] = box["os"]
    box_mod["release"] = box["release"]
    box_mod["difficultyText"] = box["difficultyText"]
    all_boxes.append(box_mod)

with open("data/htb_raw_retired.json") as f:
    data = json.load(f)

for box in data:
    # Clean the box to minimal properties
    box_mod = dict()
    box_mod["name"] = box["name"]
    box_mod["os"] = box["os"]
    box_mod["release"] = box["release"]
    box_mod["difficultyText"] = box["difficultyText"]
    all_boxes.append(box_mod)

with open("data/htb_boxes.json", "w") as f:
    json.dump(all_boxes, f, indent=4)
