#!/usr/bin/env python3

from pathlib import Path

import htb
import pg


# Add markdown header
readme = "# Trophy Room\n\n"

# Add GitHub Actions workflow builder badge
readme += (
    "![deploy workflow]"
    "(https://img.shields.io/github/actions/workflow/status/"
    "thomaslaurenson/trophyroom/deploy.yml"
    "?logo=github&color=green)\n\n"
)

# Add HTB badges
htb_badges = htb.generate_badges()
readme += htb_badges

# Add PG badges
pg_badges = pg.generate_badges()
readme += pg_badges

# Add repo/project summary
readme += """
Collection of my walkthroughs, hints, notes, code snippets, tool logs, and resources for vulnerable CTF-style boxes.\n
## Overview\n
The boxes targeted in this repo are based off the [**NetSecFocus Trophy Room** list by TJ Null](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview) - including boxes from Hack The Box and OffSec Proving Grounds. I am also trying new boxes on Hack The Box when they are released - but they will not be uploaded until the machines are retired, as per the [Hack The Box Terms of Service](https://www.hackthebox.eu/tos).
"""

# Add HTB machines contents
readme += "\n## Hack The Box\n\n"
htb_toc = htb.generate_toc_table()
readme += htb_toc

# Add PG machines contents
readme += "\n## Proving Grounds\n\n"
pg_toc = pg.generate_toc_table()
readme += pg_toc

# print(readme)
readme_path = Path().resolve().parent / "README.md"
with open(readme_path, "w") as f:
    f.write(readme)
