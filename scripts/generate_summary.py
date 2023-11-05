#!/usr/bin/env python3

import pathlib

import htb
import pg


package_dir = pathlib.Path(__file__).parent.absolute()

summary = f"# Summary\n\n" "[Introduction](./README.md)\n"

summary += "\n# Hack The Box\n\n"
htb_machines = list(htb.COMPLETED_BOX_LOOKUP.keys())
htb_machines.sort()
for htb_machine in htb_machines:
    name = htb_machine
    summary += f"- [{name}](./hackthebox/{name.lower()}/README.md)\n"

summary += "\n# Proving Grounds\n\n"
pg_machines = list(pg.COMPLETED_BOX_LOOKUP.keys())
pg_machines.sort()
for pg_machine in pg_machines:
    name = pg_machine
    summary = summary + f"- [{name}](./provinggrounds/{name.lower()}/README.md)\n"

file_path = package_dir.parent / "SUMMARY.md"
with file_path.open("w") as f:
    f.write(summary)
