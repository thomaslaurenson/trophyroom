# trophy_room

Collection of my walkthroughs, hints, notes, code snippets, tool logs, and resources for vulnerable CTF-style boxes.

![htb writeups](https://img.shields.io/badge/htb%20writeups-38-green&style=plastic?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAABhGlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AcxV9TpSoVBTuIOGSonSyIFXHUKhShQqgVWnUwufQLmjQkKS6OgmvBwY/FqoOLs64OroIg+AHi5uak6CIl/q8ptIjx4Lgf7+497t4BQr3MNKtrAtB020wl4mImuyoGXtGLQQwhgpjMLGNOkpLwHF/38PH1LsqzvM/9OfrVnMUAn0g8ywzTJt4gnt60Dc77xCFWlFXic+Jxky5I/Mh1xeU3zoUmCzwzZKZT88QhYrHQwUoHs6KpEU8Rh1VNp3wh47LKeYuzVq6y1j35C4M5fWWZ6zRHkcAiliBBhIIqSijDRpRWnRQLKdqPe/hHmn6JXAq5SmDkWEAFGuSmH/wPfndr5WOTblIwDnS/OM7HGBDYBRo1x/k+dpzGCeB/Bq70tr9SB2Y+Sa+1tfARMLANXFy3NWUPuNwBhp8M2ZSbkp+mkM8D72f0TVlg6BboW3N7a+3j9AFIU1fJG+DgEIgUKHvd4909nb39e6bV3w+413LD6ZqKlQAAAAZiS0dEABQAHQAr1GFDXgAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAd0SU1FB+UJEBMoBwoNM18AAAAZdEVYdENvbW1lbnQAQ3JlYXRlZCB3aXRoIEdJTVBXgQ4XAAACAUlEQVQoz4WST0iTYRzHv8/j2/7l/gRDFuIkEkSQmL7VCgxiHix2GBEsJnTolgc7KHgpiKAugR66zJuHgVtiyKCgSxEtaO9qortIhzHYEERS33eu951tPr8OYzKn0vf2PHy+z/P782U4RUvabV+V8rMAYGGXp8POL2vtDG89JMvBrpjaF9VFWuEwFThMBV2klZjaF02Wg12tLAOAT5VHpq16eqJOW88Zc+QsrGcq7Py22vh9ZLhKpTki7YrELr7wSDeio50Lf1lCle0HVFAE9votbHg84sq+Pa38uCo/qNLqIseFX2Z2yc8NyroEdgcA4jVsP06ostxuSqiyXMP2BEBcYHfAoKzrqEcrv34XAAxaz8TU3vllLeBZ1gKemNo7b9B6BgA1mWPDMUQm5bdNBsxsMCJIH6sIZaMilA1B+piZDUb8tsmAITKpJi+1ltRvmiEAS8nyvffq4dcPAODqGAmGHCs6sIaFvTPW0VTIsaIL7JQEdkoN00kdGTv5qBn/USvDrXxI43DndZFLx1Vf6CxTXPWFdJFLc7jzVj6kMQD4uP/Q+vvwx5M6bT7lzP7dzHqmdfFzBgBs/OrrAyrNCtq/KbHuV+6Oa2/u2GMGa331XTnQbYjiyzoVx4Hztcbtn3MS8y5auffZfcfnzWOROxnyW/4qFecaIfdOhZ0ppZ35B+U31U10XP4mAAAAAElFTkSuQmCC) ![htb oscp coverage](https://img.shields.io/badge/htb%20oscp%20coverage-42%25-green&style=plastic?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAABhGlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AcxV9TpSoVBTuIOGSonSyIFXHUKhShQqgVWnUwufQLmjQkKS6OgmvBwY/FqoOLs64OroIg+AHi5uak6CIl/q8ptIjx4Lgf7+497t4BQr3MNKtrAtB020wl4mImuyoGXtGLQQwhgpjMLGNOkpLwHF/38PH1LsqzvM/9OfrVnMUAn0g8ywzTJt4gnt60Dc77xCFWlFXic+Jxky5I/Mh1xeU3zoUmCzwzZKZT88QhYrHQwUoHs6KpEU8Rh1VNp3wh47LKeYuzVq6y1j35C4M5fWWZ6zRHkcAiliBBhIIqSijDRpRWnRQLKdqPe/hHmn6JXAq5SmDkWEAFGuSmH/wPfndr5WOTblIwDnS/OM7HGBDYBRo1x/k+dpzGCeB/Bq70tr9SB2Y+Sa+1tfARMLANXFy3NWUPuNwBhp8M2ZSbkp+mkM8D72f0TVlg6BboW3N7a+3j9AFIU1fJG+DgEIgUKHvd4909nb39e6bV3w+413LD6ZqKlQAAAAZiS0dEABQAHQAr1GFDXgAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAd0SU1FB+UJEBMoBwoNM18AAAAZdEVYdENvbW1lbnQAQ3JlYXRlZCB3aXRoIEdJTVBXgQ4XAAACAUlEQVQoz4WST0iTYRzHv8/j2/7l/gRDFuIkEkSQmL7VCgxiHix2GBEsJnTolgc7KHgpiKAugR66zJuHgVtiyKCgSxEtaO9qortIhzHYEERS33eu951tPr8OYzKn0vf2PHy+z/P782U4RUvabV+V8rMAYGGXp8POL2vtDG89JMvBrpjaF9VFWuEwFThMBV2klZjaF02Wg12tLAOAT5VHpq16eqJOW88Zc+QsrGcq7Py22vh9ZLhKpTki7YrELr7wSDeio50Lf1lCle0HVFAE9votbHg84sq+Pa38uCo/qNLqIseFX2Z2yc8NyroEdgcA4jVsP06ostxuSqiyXMP2BEBcYHfAoKzrqEcrv34XAAxaz8TU3vllLeBZ1gKemNo7b9B6BgA1mWPDMUQm5bdNBsxsMCJIH6sIZaMilA1B+piZDUb8tsmAITKpJi+1ltRvmiEAS8nyvffq4dcPAODqGAmGHCs6sIaFvTPW0VTIsaIL7JQEdkoN00kdGTv5qBn/USvDrXxI43DndZFLx1Vf6CxTXPWFdJFLc7jzVj6kMQD4uP/Q+vvwx5M6bT7lzP7dzHqmdfFzBgBs/OrrAyrNCtq/KbHuV+6Oa2/u2GMGa331XTnQbYjiyzoVx4Hztcbtn3MS8y5auffZfcfnzWOROxnyW/4qFecaIfdOhZ0ppZ35B+U31U10XP4mAAAAAElFTkSuQmCC)

## Overview

The boxes targeted in this repo are based off the **NetSecFocus Trophy Room** list by TJ Null, available as a [Google Sheet](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview). In addition, I am trying new boxes on Hack The Box when they are released - but they will not be uploaded until the machines are retired, as per the [Hack The Box Terms of Service](https://www.hackthebox.eu/tos).

## Hack The Box

### Starting Point

| Name | System | Difficulty | Trophy List | Release Date | Published Date |
| ---- |--------|------------|-------------|--------------|----------------|
| [Archetype](hackthebox/startingpoint/1_archetype) | Windows | Very Easy | No | 2020-12-01 | 2021-07-08 |
| [Oopsie](hackthebox/startingpoint/2_oopsie) | Linux | Very Easy | No | 2020-12-01 | 2021-07-10 |
| [Vaccine](hackthebox/startingpoint/3_vaccine) | Linux | Very Easy | No | 2020-12-01 | 2021-07-11 |
| [Shield](hackthebox/startingpoint/4_shield) | Windows | Very Easy | No | 2020-12-01 | 2021-07-29 |

### Machines

| Name | System | Difficulty | Trophy List | Release Date | Published Date |
| ---- |--------|------------|-------------|--------------|----------------|
| [Admirer](hackthebox/machines/admirer) | Linux | Easy | Yes | 2020-05-02 | 2021-09-22 |
| [Armageddon](hackthebox/machines/armageddon) | Linux | Easy | No | 2021-03-27 | 2021-07-26 |
| [Bashed](hackthebox/machines/bashed) | Linux | Easy | Yes | 2017-12-09 | 2021-06-27 |
| [Beep](hackthebox/machines/beep) | Linux | Easy | Yes | 2017-03-14 | 2021-07-03 |
| [Blocky](hackthebox/machines/blocky) | Linux | Easy | Yes | 2017-07-21 | 2021-09-04 |
| [Blue](hackthebox/machines/blue) | Windows | Easy | Yes | 2017-07-28 | 2021-10-04 |
| [Blunder](hackthebox/machines/blunder) | Linux | Easy | Yes | 2020-05-30 | 2021-09-21 |
| [Cronos](hackthebox/machines/cronos) | Linux | Medium | Yes | 2017-03-22 | 2021-07-04 |
| [Delivery](hackthebox/machines/delivery) | Linux | Easy | Yes | 2021-01-09 | 2021-09-05 |
| [Devel](hackthebox/machines/devel) | Windows | Easy | Yes | 2017-03-14 | 2021-07-25 |
| [Doctor](hackthebox/machines/doctor) | Linux | Easy | Yes | 2020-09-26 | 2021-09-28 |
| [FriendZone](hackthebox/machines/friendzone) | Linux | Easy | Yes | 2019-02-09 | 2021-09-30 |
| [Irked](hackthebox/machines/irked) | Linux | Easy | Yes | 2018-11-17 | 2021-09-20 |
| [Jerry](hackthebox/machines/jerry) | Windows | Easy | Yes | 2018-06-30 | 2021-08-20 |
| [Knife](hackthebox/machines/knife) | Linux | Easy | No | 2021-05-22 | 2021-08-30 |
| [Lame](hackthebox/machines/lame) | Linux | Easy | Yes | 2017-03-14 | 2021-06-27 |
| [Legacy](hackthebox/machines/legacy) | Windows | Easy | Yes | 2017-03-14 | 2021-07-25 |
| [Love](hackthebox/machines/love) | Windows | Easy | No | 2021-05-01 | 2021-08-14 |
| [Networked](hackthebox/machines/networked) | Linux | Easy | Yes | 2019-08-24 | 2021-09-26 |
| [Nibbles](hackthebox/machines/nibbles) | Linux | Easy | Yes | 2018-01-13 | 2021-07-03 |
| [Nineveh](hackthebox/machines/nineveh) | Linux | Medium | Yes | 2017-08-04 | 2021-07-06 |
| [OpenAdmin](hackthebox/machines/openadmin) | Linux | Easy | Yes | 2020-01-04 | 2021-08-05 |
| [Ophiuchi](hackthebox/machines/ophiuchi) | Linux | Medium | Yes | 2021-02-13 | 2021-08-19 |
| [Popcorn](hackthebox/machines/popcorn) | Linux | Medium | Yes | 2017-03-14 | 2021-07-26 |
| [Postman](hackthebox/machines/postman) | Linux | Easy | Yes | 2019-11-02 | 2021-09-04 |
| [Schooled](hackthebox/machines/schooled) | FreeBSD | Medium | No | 2021-04-03 | 2021-09-15 |
| [Sense](hackthebox/machines/sense) | FreeBSD | Easy | Yes | 2017-10-21 | 2021-07-16 |
| [Shocker](hackthebox/machines/shocker) | Linux | Easy | Yes | 2017-09-30 | 2021-06-27 |
| [Spectra](hackthebox/machines/spectra) | Other | Easy | No | 2021-02-27 | 2021-07-21 |
| [SwagShop](hackthebox/machines/swagshop) | Linux | Easy | Yes | 2019-05-11 | 2021-09-13 |
| [Tabby](hackthebox/machines/tabby) | Linux | Easy | Yes | 2020-06-20 | 2021-08-18 |
| [TheNotebook](hackthebox/machines/thenotebook) | Linux | Medium | No | 2021-03-06 | 2021-07-03 |
| [Valentine](hackthebox/machines/valentine) | Linux | Easy | Yes | 2018-02-17 | 2021-09-17 |
| [Writeup](hackthebox/machines/writeup) | Linux | Easy | No | 2019-06-08 | 2021-08-04 |
