#!/usr/bin/env python3

import pathlib


print("[+] 1. Hack The Box")
print("[+] 2. VulnHub")
print("[+] 3. Proving Grounds")
machine_provider = input("[+] Enter machine provider [1/2/3]: ")
if machine_provider == "1":
    machine_provider = "hackthebox"
elif machine_provider == "2":
    machine_provider = "vulnhub"
elif machine_provider == "3":
    machine_provider = "provinggrounds"
else:
    print("[-] Not a valid choice. Exiting.")
    exit(1)

machine_name = input("[+] Enter machine name: ")
machine_name = machine_name.lower()

machine_path = pathlib.Path(machine_provider) / machine_name

if machine_path.is_dir():
    print("[+] Directory exists. Exiting.")
    exit(1)
else:
    print(f"[+] Creating: {machine_path}")

machine_path.mkdir(parents=True, exist_ok=True)

# Create required files
readme = (
    f"# {machine_name}: 10.10.10.XX\n\n"
    "## Hints\n\n"
    "- HERE\n"
    "- HERE\n"
    "- HERE\n\n"
    "## nmap\n\n"
    "Starting with the usual `nmap` scan. Interesting ports:\n\n"
    "```none\n"
    "TODO\n"
    "```\n\n"
    "## 80: Recon\n\n"
    "TODO\n\n"
    "![80 Home](screenshots/80_home.png)\n\n"
    "Code\n\n"
    "```none\n"
    "TODO\n"
    "```\n\n"
    "## Privesc: `www-data` to `user`\n\n"
    "TODO\n\n"
    "## Privesc: `user` to `root`\n\n"
    "TODO\n\n"
    "## Lessons Learned\n\n"
    "- TODO\n"
    "- TODO\n\n"
    "## Useful Resources\n\n"
    "- [Name](LINK)\n"
    "- [Name](LINK)\n"
)

filepath = machine_path / "README.md"
with filepath.open("w") as f:
    f.write(readme)

filepath = machine_path / "NOTES.md"
filepath.touch()

filepath = machine_path / "ip"
filepath.touch()

# Create required folders
folders = ["exploits", "files", "logs", "screenshots"]

for folder in folders:
    folder_path = machine_path / folder
    folder_path.mkdir()
