import json

# https://portal.offsec.com/api/learning-units/1/full > pg_play_raw.json
# https://portal.offsec.com/api/learning-units/2/full > pg_practice_raw.json

all_boxes = list()

with open("data/pg_raw_play.json") as f:
    pg_play_raw = json.load(f)

# Grab "All" child
for children in pg_play_raw["children"]:
    # Only process the "All" list
    name = children["name"]
    if name != "All":
        continue

    boxes = children["children"]
    boxes_mod = list()

    # Clean the box to minimal properties
    for box in boxes:
        box_mod = dict()
        box_mod["name"] = box["name"]
        box_mod["primary_os"] = box["primary_os"]
        box_mod["difficulty"] = box["difficulty"]
        box_mod["release_date"] = box["release_date"]
        box_mod["type"] = "play"
        boxes_mod.append(box_mod)

    all_boxes.extend(boxes_mod)

with open("data/pg_raw_practice.json") as f:
    pg_practice_raw = json.load(f)

# Grab "All" child
for children in pg_practice_raw["children"]:
    # Only process the "All" list
    name = children["name"]
    if name != "All":
        continue

    boxes = children["children"]
    boxes_mod = list()

    # Clean the box to minimal properties
    for box in boxes:
        box_mod = dict()
        box_mod["name"] = box["name"]
        box_mod["primary_os"] = box["primary_os"]
        box_mod["difficulty"] = box["difficulty"]
        box_mod["release_date"] = box["release_date"]
        box_mod["type"] = "practice"
        boxes_mod.append(box_mod)

    all_boxes.extend(boxes_mod)

with open("data/pg_boxes.json", "w") as f:
    json.dump(all_boxes, f, indent=4)
