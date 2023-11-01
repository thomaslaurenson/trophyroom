#!/usr/bin/env python3

import pathlib


package_dir = pathlib.Path(__file__).parent.absolute()

summary = f"# Summary\n\n" "[Introduction](./README.md)\n\n" "# Hack The Box\n\n"

htb_dir = package_dir.parent / "hackthebox"
htb_machines = list(htb_dir.glob("*"))
for htb_machine in htb_machines:
    name = htb_machine.stem
    summary = summary + f"- [{name}](./hackthebox/{name}/README.md)\n"

file_path = package_dir.parent / "SUMMARY.md"
with file_path.open("w") as f:
    f.write(summary)
