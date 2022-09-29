# Week 3 work

## Identification
* [CVE-2021-30481](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30481)
* Remote code execution that allows remoted authenticated users to execute arbitrary code due to a buffer overflow.
* The attack occurs when the user clicks an invitation link to a Source game engine that is previously installed.
## Cataloguing
* On December 10, 2020 @floesen_ [tweeted](https://twitter.com/floesen_/status/1337107178096881666) that he received a bugbounty to a Classic Buffer Overflow vulnerability.
* This vulnerability was reported to Valve on June 5, 2019 with a severity of 9.0.
* It was officially reported to CVE only two years after on April 10, 2021 when @the_secret_club [posted](https://twitter.com/the_secret_club/status/1380868759129296900) a video demonstrating a remote code execution attack using this vulnerability.
* NVD and MITRE classify this vulnerability with a severity of 9.0 and 8.0 respectively.

## Exploit

* As mentioned before, this attack consists in an user clicking an invitation link to a Source game engine exposing the majority of the Steam users. 
* This happens due to a buffer overflow error leading to the attacker gaining full control of the users pc.
* With this in mind the atacker can access/manipulate anything on the user's computer, as well as executing his own code.

## Known attacks

* The attacker can gain access to the shell, thus having full control of the user's computer.
* The first known report of this attack was made by @floesen_ exposing the exploit and manifesting that more Steam users were also victims of this vulnerability.
* After years of Valve not acknowledging this exploit, three more users tweeted a video showcasing their remote code execution through this vulnerability.
