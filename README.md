# Trophy Room

![deploy workflow](https://img.shields.io/github/actions/workflow/status/thomaslaurenson/trophyroom/deploy.yml?logo=github&color=green)

![htb writeups](https://img.shields.io/badge/htb_writeups-35-green?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAABmJLR0QA/wD/AP+gvaeTAAABzklEQVQoz41SPWgTYRh+vu8uLTbkeqiolyFkaRoKEUpKKYWCONRmiMUihda0i6ODoFApzg4KCg5udWkMXEUUdGizSLp1qKUYh6NZSksJgrH3XZo76CXf6yDVpGnQZ3p53+f9f4AOMEVy2BTJ4U5xdtrx3kkZNWk9k/TjJgBwdvFjkMcXprTVcjOPnxhrR3PdOXtg0WlsWAD3NWW0X1NG+wHuO40NK2cPLK4dzXW3dMzZfdfr9PM1EPh+jsfvTfcWvjRXfyuuJT1pvQL8yyo7f/eOXvrMAeCYShmJShQgAXjV9o28KkBCohI9plIGANS/MxtLjKmXXLn1LWtHXgbZ1ScAUKOvj125dZ+zK6ucjCWJstKyo0R5e17fn+xi8bQkL+XIdcuR65YkL9XF4ul5fX9SorzddpwTzOrFvKFODALKJqBsGurE4KxezJ/m8bN+NB7K+gT7gGAfjIey/lmcP4kKwlH8A80cDgABFlshuDPLh+GCKYYS7SoaSiwfhgsEdybAYistyvlUvdUjGsVHdao8UJj2RpIb+a2cnr0GORmVXXjRqySepkMf3A6SuxGpyZ3nddq9DQAqi74L8tjDKS2/h/+BKUbGTDEy1in+CwRytDFQHtyiAAAAAElFTkSuQmCC) ![htb oscp coverage](https://img.shields.io/badge/htb_oscp_coverage-33%25-green?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAABmJLR0QA/wD/AP+gvaeTAAABzklEQVQoz41SPWgTYRh+vu8uLTbkeqiolyFkaRoKEUpKKYWCONRmiMUihda0i6ODoFApzg4KCg5udWkMXEUUdGizSLp1qKUYh6NZSksJgrH3XZo76CXf6yDVpGnQZ3p53+f9f4AOMEVy2BTJ4U5xdtrx3kkZNWk9k/TjJgBwdvFjkMcXprTVcjOPnxhrR3PdOXtg0WlsWAD3NWW0X1NG+wHuO40NK2cPLK4dzXW3dMzZfdfr9PM1EPh+jsfvTfcWvjRXfyuuJT1pvQL8yyo7f/eOXvrMAeCYShmJShQgAXjV9o28KkBCohI9plIGANS/MxtLjKmXXLn1LWtHXgbZ1ScAUKOvj125dZ+zK6ucjCWJstKyo0R5e17fn+xi8bQkL+XIdcuR65YkL9XF4ul5fX9SorzddpwTzOrFvKFODALKJqBsGurE4KxezJ/m8bN+NB7K+gT7gGAfjIey/lmcP4kKwlH8A80cDgABFlshuDPLh+GCKYYS7SoaSiwfhgsEdybAYistyvlUvdUjGsVHdao8UJj2RpIb+a2cnr0GORmVXXjRqySepkMf3A6SuxGpyZ3nddq9DQAqi74L8tjDKS2/h/+BKUbGTDEy1in+CwRytDFQHtyiAAAAAElFTkSuQmCC)

![pg writeups](https://img.shields.io/badge/pg_writeups-0-blue?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAABmJLR0QA/wD/AP+gvaeTAAABhUlEQVQoz32RwUsVURjFf984c7/p5aIQhBQUImxhSc9/wkVgaxFBBZ8LN7nJRf9DSLUIAoWglRAmPEOxPyBm1LdxIUIRLty5kHtnXDUtZkbH6dmBC+dyz7nn3O9CBaYdDQTb0SJAz070qmcnagEE3+KWaUf9Va1Xkt6NeC64lBOTygJAaIXQSn5hkrWCS/nVuxHP3DD2rccLJmVNHQ11+YG6fOVcUEfDpHzqW49nAfzBd/uP/6TZKjWo7c4F3g++3f/um4RlRBp1Y1mzzoG7ZCz76pikC25LLPDCV8uDW4zef4wP/dAKWRdjaOUecFFWrWoE8NVyBpVU4bxIuQ+EBa9n/vTU8VWtoBbUCsbxoayqljv5P/LxWgPq2PKCVFbVkagV1PFjb3P8S26Up6GVRwB7m+Of1XGUayQxqbzxtnebxybhZejAJKxcv5FhtQxdDSjhdaFZau82T69KT411Jko+M9IJp0cPs+nRzo25TY0dPq8O6B/MD3eawEGxfbL2+9lRXfMX0dWGp3g7yHUAAAAASUVORK5CYII=) ![pg oscp coverage](https://img.shields.io/badge/pg_oscp_coverage-0%25-blue?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAABmJLR0QA/wD/AP+gvaeTAAABhUlEQVQoz32RwUsVURjFf984c7/p5aIQhBQUImxhSc9/wkVgaxFBBZ8LN7nJRf9DSLUIAoWglRAmPEOxPyBm1LdxIUIRLty5kHtnXDUtZkbH6dmBC+dyz7nn3O9CBaYdDQTb0SJAz070qmcnagEE3+KWaUf9Va1Xkt6NeC64lBOTygJAaIXQSn5hkrWCS/nVuxHP3DD2rccLJmVNHQ11+YG6fOVcUEfDpHzqW49nAfzBd/uP/6TZKjWo7c4F3g++3f/um4RlRBp1Y1mzzoG7ZCz76pikC25LLPDCV8uDW4zef4wP/dAKWRdjaOUecFFWrWoE8NVyBpVU4bxIuQ+EBa9n/vTU8VWtoBbUCsbxoayqljv5P/LxWgPq2PKCVFbVkagV1PFjb3P8S26Up6GVRwB7m+Of1XGUayQxqbzxtnebxybhZejAJKxcv5FhtQxdDSjhdaFZau82T69KT411Jko+M9IJp0cPs+nRzo25TY0dPq8O6B/MD3eawEGxfbL2+9lRXfMX0dWGp3g7yHUAAAAASUVORK5CYII=)

Collection of my walkthroughs, hints, notes, code snippets, tool logs, and resources for vulnerable CTF-style boxes.

## Overview

The boxes targeted in this repo are based off the [**NetSecFocus Trophy Room** list by TJ Null](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview). In addition, I am trying new boxes on Hack The Box when they are released - but they will not be uploaded until the machines are retired, as per the [Hack The Box Terms of Service](https://www.hackthebox.eu/tos).

## Hack The Box

| Name | System | Difficulty | Trophy List | Release Date | Published Date |
| ---- |--------|------------|-------------|--------------|----------------|
| [Admirer](hackthebox/admirer) | Linux | Easy | Yes | 2020-05-02 | 2021-09-22 |
| [Armageddon](hackthebox/armageddon) | Linux | Easy | No | 2021-03-27 | 2021-07-26 |
| [Bashed](hackthebox/bashed) | Linux | Easy | Yes | 2017-12-09 | 2021-06-27 |
| [Beep](hackthebox/beep) | Linux | Easy | Yes | 2017-03-14 | 2021-07-03 |
| [Blocky](hackthebox/blocky) | Linux | Easy | Yes | 2017-07-21 | 2021-09-04 |
| [Blue](hackthebox/blue) | Windows | Easy | Yes | 2017-07-28 | 2021-10-04 |
| [Blunder](hackthebox/blunder) | Linux | Easy | Yes | 2020-05-30 | 2021-09-21 |
| [Cronos](hackthebox/cronos) | Linux | Medium | Yes | 2017-03-22 | 2021-07-04 |
| [Delivery](hackthebox/delivery) | Linux | Easy | Yes | 2021-01-09 | 2021-09-05 |
| [Devel](hackthebox/devel) | Windows | Easy | Yes | 2017-03-14 | 2021-07-25 |
| [Doctor](hackthebox/doctor) | Linux | Easy | Yes | 2020-09-26 | 2021-09-28 |
| [FriendZone](hackthebox/friendzone) | Linux | Easy | Yes | 2019-02-09 | 2021-09-30 |
| [Irked](hackthebox/irked) | Linux | Easy | Yes | 2018-11-17 | 2021-09-20 |
| [Jerry](hackthebox/jerry) | Windows | Easy | Yes | 2018-06-30 | 2021-08-20 |
| [Knife](hackthebox/knife) | Linux | Easy | Yes | 2021-05-22 | 2021-08-30 |
| [Lame](hackthebox/lame) | Linux | Easy | Yes | 2017-03-14 | 2021-06-27 |
| [Legacy](hackthebox/legacy) | Windows | Easy | Yes | 2017-03-14 | 2021-07-25 |
| [Love](hackthebox/love) | Windows | Easy | Yes | 2021-05-01 | 2021-08-14 |
| [Networked](hackthebox/networked) | Linux | Easy | Yes | 2019-08-24 | 2021-09-26 |
| [Nibbles](hackthebox/nibbles) | Linux | Easy | Yes | 2018-01-13 | 2021-07-03 |
| [Nineveh](hackthebox/nineveh) | Linux | Medium | Yes | 2017-08-04 | 2021-07-06 |
| [OpenAdmin](hackthebox/openadmin) | Linux | Easy | Yes | 2020-01-04 | 2021-08-05 |
| [Ophiuchi](hackthebox/ophiuchi) | Linux | Medium | Yes | 2021-02-13 | 2021-08-19 |
| [Paper](hackthebox/paper) | Linux | Easy | Yes | 2022-02-05 | 2023-10-30 |
| [Popcorn](hackthebox/popcorn) | Linux | Medium | Yes | 2017-03-14 | 2021-07-26 |
| [Postman](hackthebox/postman) | Linux | Easy | Yes | 2019-11-02 | 2021-09-04 |
| [Schooled](hackthebox/schooled) | FreeBSD | Medium | No | 2021-04-03 | 2021-09-15 |
| [Sense](hackthebox/sense) | OpenBSD | Easy | Yes | 2017-10-21 | 2021-07-16 |
| [Shocker](hackthebox/shocker) | Linux | Easy | Yes | 2017-09-30 | 2021-06-27 |
| [Spectra](hackthebox/spectra) | Other | Easy | No | 2021-02-27 | 2021-07-21 |
| [SwagShop](hackthebox/swagshop) | Linux | Easy | Yes | 2019-05-11 | 2021-09-13 |
| [Tabby](hackthebox/tabby) | Linux | Easy | Yes | 2020-06-20 | 2021-08-18 |
| [TheNotebook](hackthebox/thenotebook) | Linux | Medium | No | 2021-03-06 | 2021-07-03 |
| [Valentine](hackthebox/valentine) | Linux | Easy | Yes | 2018-02-17 | 2021-09-17 |
| [Writeup](hackthebox/writeup) | Linux | Easy | No | 2019-06-08 | 2021-08-04 |
