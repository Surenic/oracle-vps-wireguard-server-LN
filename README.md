# Wireguard Server für Lightning Node und Services in der Oracle Cloud (Free Tier)
Tutorial zum Aufsetzen eines Wireguard VPN Servers auf einem kostenlosen Oracle Cloud VPS

Diese Anleitung soll als Hilfestellung dienen, eine bestehende Raspiblitz Full Node, dessen Lightning-Implementierung und gewünschte Dienste über die VPN-Clearnet-Adresse freizugeben. Ohne diverse Anleitungen von [TrezorHannes](https://github.com/TrezorHannes) wäre diese hier nicht entstanden. Daher danke für den massiven Input an dieser Stelle.

### Voraussetzungen
- Ein Oracle Cloud Free Tier Account ([Link](https://www.oracle.com/cloud/free/)). Dieser erfordert Klarnamen-Einträge, die am Ende der Account-Erstellung mit der Eingabe von Kreditkarten-Daten und einer Ab- und Rückbuchung von 1$ bestätigt werden. Im Verlauf des Tutorials werden wir lediglich Produkte "buchen", die als "immer kostenlos" deklariert werden. Der Free Tier Account hat gewisse Einschränkungen in Sachen Anzahl aktiver Instanzen und Traffic, die hierfür aber mehr als ausreichend sein sollten.
- eine laufende Lightning Node (in diesem Tutorial gehe ich speziell auf Raspiblitz ein. Es lässt sich aber auch auf andere Implementierungen übertragen)
- Macht euch Gedanken darüber, welche Services ihr über das Clearnet erreichen wollt und notiert euch die benötigten Ports (z.B. LND 9735, CLN 9736, LNbits 5001, Electrum Server 50002 uws.)

### Anmerkung
Falls ihr über eine eigene Domain verfügt, lassen sich Dienste über einen nginx Reverse Proxy Server über Subdomains (bspw. lnbits.domain.org) verfügbar machen, ohne dass die entsprechenden Ports freigegeben werden müssen. Ruft dazu gern im Anschluss [dieses Tutorial hier](https://github.com/Surenic/reverse-proxy-node-services) auf.

## VPS Server Setup

1. Loggt euch in euren Oracle Cloud Account
2. Klickt oben links auf die drei Balken, wählt "Compute" und dann "Instanzen". Wird hier keine Möglichkeit zum Erstellen einer neuen Instanz angezeigt, wählt links unter "Compartment" euren Benutzernamen aus.
3. Nun könnt ihr eine neue Instanz erstellen
4.  - Der Name ist frei wählbar
    - Compartment zeigt euren gewählten Oracle-Account-Namen
    - Platzierung zeigt den Serverstandort
    - Als Image wählt ihr "Canonical Ubuntu"
    - Die Shape bleibt unverändert
    - Unter "Networking" werden automatisch ein Cloud-Netzwerk und ein Subnetzwerk eingerichtet. Dies kann so bleiben.
    - SSH Key: Um via SSH Zugriff auf den Ubuntu Server zu bekommen, braucht ihr einen Public Key, sowie den dazugehörigen Private Key. Wie das geht erfahrt ihr [hier](https://www.oracle.com/webfolder/technetwork/tutorials/obe/cloud/compute-iaas/generating_ssh_key/generate_ssh_key.html#section1s2). Unter Windows könnt ihr die "Windows Power Shell" oder puTTY benutzen.
5. Ist der Public Key erfolgreich hochgeladen oder eingefügt, klickt ihr auf "Erstellen"


## VPS Server Konfiguration

1. Ist die Instanz hochgefahren, seht ihr unter Instanzzugriff euren Benutzernamen (ubuntu) sowie die öffentliche IP-Adresse eures Servers (im weiteren Verlauf `PUBLIC_IP`). Notiert diese.
2. Unter Instanzdetails klickt ihr den Link zu eurem Virtuellen Cloud-Netzwerk, im folgenden Fenster auf euer Subnetz und dann wiederum auf eure "Default Security List". Hier müssen nun einige Portfreigaben eingerichtet werden
3. Unter "Impress-Regeln hinzufügen" fügt ihr folgendes ein:
   - Quell-CIDR: `0.0.0.0/0`
   - IP-Protokoll: `UDP`
   - Zielportbereich: `51820`
   und klickt auf Impress-Regeln hinzufügen
4. Wiederholt Schritt 3, wählt statt `UDP` `TCP` und tragt bei Zielportbereich mit Kommata getrennt alle Ports ein, die ihr später entsprechend der Dienste freigeben wollt. Der Wichtigste ist hier die `9735` und/oder die `9736` für die Node. 


## VPS Server-Zugriff und Einrichtung

Nehmt euren SSH-Client zur Hand und verbindet euch mit eurem Server mittels des zuvor erstellten private keys. Im Falle des Linux-Terminals sieht das so aus

```
ssh ubuntu@PUBLIC_IP -i PATH_TO_PRIVATE_KEY/PRIVATE_KEY_FILE
```

Der Pfad und die File für die ssh-Schlüssel ist unter Linux standardmäßig `~/.ssh/id_rsa`

Nun führt ihr einige Befehle aus, um die Instanz auf den neuesten Stand zu bringen und entsprechend vorzubereiten.

```
sudo apt update
sudo apt upgrade -y
sudo shutdown -r now
```

Der letzte Befehl startet die Instanz neu. Das kann einige Zeit dauern. Holt euch einen Kaffee und loggt euch nach einer Weile via ssh wieder ein. Dann geht es weiter. Zunächst setzen wir alle Regeln der vorinstallierten Firewall zurück und installieren zusätzlich die etwas einfacher zu bedienende UFW (Uncomplicated Firewall):

```
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -F
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 51820/udp
sudo ufw allow OpenSSH
sudo ufw allow 22
```

Zusätzlich müssen wir alle benötigten Ports öffnen, die von den benötigten Diensten verwendet werden:

```
sudo ufw allow PORT comment 'CUSTOM'
```

Hinweis: Für `PORT` setzt ihr den gewünschten Port sowie für `CUSTOM` einen entsprechenden Namen ein (z.B LND NODE, LNbits) und wiederholt den Command mit allen gewünschten Ports. Im Zweifel kann dies auch nachträglich geschehen.

```
sudo ufw enable
```

Es kommt eine Warnung, dass möglicherweise die SSH-Verbindung gekappt wird. Da wir OpenSSH freigegeben haben, sollte dies nicht passieren.

Zu guter Letzt:

```
sudo apt install fail2ban
```
um den SSH-user zu schützen

## Wireguard Installation auf dem VPS

```
sudo apt update && sudo apt install wireguard
```
installiert Wireguard

```
wg genkey | sudo tee /etc/wireguard/private.key
sudo chmod go= /etc/wireguard/private.key
sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key
```
erzeugt den Private und Public Key eures VPS. Notiert diese in einem separaten Fenster (Editor o.ä.), wir werden beide Keys bald brauchen.

Wählt nun einen IP-Bereich, der in eurem Netzwerk nicht genutzt wird. Wird nutzen hier 10.8.0.0 - 10.255.255.255 (10/8 prefix) und ordnen dem VPS die IP 10.8.0.1 und der Node die 10.8.0.2 zu.

Erstellt eine VPS WG configuration: 

```
sudo nano /etc/wireguard/wg0.conf
```

und kopiert folgende Zeilen in die File hinein. Für den Private Key setzt ihr den zuvor erstellten Key ein:

```
[Interface]
PrivateKey = ***base64_encoded_private_key_goes_here***
Address = 10.8.0.1/24
ListenPort = 51820
SaveConfig = true
```

STRG+X, dann Y/J und Enter speichert die Datei.

Da ihr Anfragen an den Server zur Node weiterleiten wollt, muss die sysctl noch angepasst werden:

```
sudo nano /etc/sysctl.conf
```

`net.ipv4.ip_forward=1` muss entkommentiert werden. Speichern mit STRG+X, dann Y/J und Enter.

```
sudo sysctl -p
```

zum refreshen.

## Firewall und Weiterleitung auf dem VPS

Um die Weiterleitung zu aktivieren, müssen noch zusätzliche Regeln in die wg0.conf geschrieben werden, die beim Starten des WG Servers geladen werden. Hierzu ist es wichtig, die Beschreibung eures Ethernet Adapters zu kennen. Bei Oracle Cloud Servern heißt dieser in der Regel ens3. Herausfinden könnt ihr das mit
```
ip route list default
```

Habt ihr den Adapternamen, öffnet ihr die wg0.conf wie zuvor mit 

```
sudo nano /etc/wireguard/wg0.conf
```

und fügt folgende Zeilen ans Ende an:

```
PostUp = ufw route allow in on wg0 out on ens3
PostUp = iptables -t nat -I POSTROUTING -o ens3 -j MASQUERADE
PreDown = ufw route delete allow in on wg0 out on ens3
PreDown = iptables -t nat -D POSTROUTING -o ens3 -j MASQUERADE
```

Achtet auf den Adapternamen und ändert ihn ggf. ab. Speichert die Datei mit STRG+X, Y/J und Enter.

Nun müssen die Anfragen an SERVER_IP:PORT an den jeweiligen Port der Node weitergereicht werden. Hierzu müssen folgende iptables Befehle ausgeführt werden. Achtet erneut auf den Adapternamen:

```
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -i ens3 -o wg0 -p tcp --syn --dport 9735 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -i ens3 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i wg0 -o ens3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A PREROUTING -i ens3 -p tcp --dport 9735 -j DNAT --to-destination 10.8.0.2
sudo iptables -t nat -A POSTROUTING -o wg0 -p tcp --dport 9735 -d 10.8.0.2 -j SNAT --to-source 10.8.0.1
```

Mittels dieser Befehle werden Anfragen an den Port 9735 des Servers (10.8.0.1) an die IP und Port der Node (10.8.0.2) weitergeleitet. Wiederholt die 3 Befehle die `--dport 9735` enthalten mit sämtlichen Ports die ihr freigeben bzw. weiterleiten wollt. Z.B. für Zeus (6100)

```
sudo iptables -A FORWARD -i ens3 -o wg0 -p tcp --syn --dport 6100 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -t nat -A PREROUTING -i ens3 -p tcp --dport 6100 -j DNAT --to-destination 10.8.0.2
sudo iptables -t nat -A POSTROUTING -o wg0 -p tcp --dport 6100 -d 10.8.0.2 -j SNAT --to-source 10.8.0.1
```

Um all diese Einstellungen bei einem Neustart des Servers zu speichern, gebt ihr noch folgende Befehle ein:

```
sudo apt install netfilter-persistent
sudo apt install iptables-persistent
sudo netfilter-persistent save
sudo systemctl enable netfilter-persistent
```

### Starten des Wireguard Servers

```
sudo systemctl enable wg-quick@wg0.service
sudo systemctl start wg-quick@wg0.service
sudo systemctl status wg-quick@wg0.service
```

Der erste Befehl macht den Wireguard Server zu einem Dienst, der Zweite startet ihn und mittels des Dritten checkt ihr den Status. Der Server sollte nun laufen und über Port UDP 51820 erreichbar sein.

## Installation des Wireguard Clients auf der Node

Loggt euch via Terminal auf eurem Raspiblitz ein und installiert Wireguard wie folgt. Speichert dabei wie zuvor den Private und Public Key eurer Node separat:

```
sudo apt update
sudo apt install wireguard -y
sudo apt install resolvconf -y
wg genkey | sudo tee /etc/wireguard/private.key
sudo chmod go= /etc/wireguard/private.key
sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key
```

Wie zuvor erstellen wir auch auf der Node eine wg0.conf

```
sudo nano /etc/wireguard/wg0.conf
```

Tragt folgende Zeilen ein und ergänzt die nötigen Angaben wie Private Key der Node, Public Key des VPS und SERVER_IP (Endpoint) des VPS

```
[Interface]
PrivateKey = ***base64_encoded_peer_private_key_goes_here***
Address = 10.8.0.2/24

[Peer]
PublicKey = ***base64_encoded_peer_public_key_goes_here***
AllowedIPs = 0.0.0.0/0
Endpoint = PUBLIC_IP:51820
PersistentKeepalive = 25
```

Würden wir den Wireguard Client nun starten, würde dieser versuchen, sich mit dem VPS verbinden, würde aber die lokale Anbindung verlieren. Ein Zugriff wäre dann nur über den VPS möglich. Um das zu verhindern fügen wir noch folgende Zeilen in die wg0.conf unten an. Die `LOCAL_NODE_IP` ist dabei die IP eurer Node im Heimnetzwerk, die `LOCAL_ROUTER_IP` die lokale IP eures Routers und `DNS-ADRESSE-DES-VPS` die DNS IP des VPS, die ihr mittels des Befehls `resolvectl dns ens3` auf dem Server ermitteln könnt.

```
PostUp = ip rule add table 200 from LOCAL_NODE_IP
PostUp = ip route add table 200 default via LOCAL_ROUTER_IP
PreDown = ip rule delete table 200 from LOCAL_NODE_IP
PreDown = ip route delete table 200 default via LOCAL_ROUTER_IP

DNS = DNS-ADRESSE-DES-VPS
```

Zu guter Letzt müssen wir dem VPS Server nun mitteilen bzw. erlauben, dass sich die Node mit diesem verbinden darf. Dazu muss der Public Key der Node am VPS Server registriert werden. Wir wechseln also erneut in das Terminal-Fenster des VPS

```
sudo wg set wg0 peer NODE_PUBLIC_KEY allowed-ips 10.8.0.2
```

Ob es richtig eingetragen ist, könnt ihr mittels `sudo wg` überprüfen.

Nun kommt die Stunde der Wahrheit:

Im Terminal-Fenster der Node verbinden wir den WG-Client mit dem Server

```
sudo wg-quick up wg0
```
stellt eine kurze Verbindung her. Checkt via `sudo wg` sowohl auf der Node als auch auf dem Server, ob eine Verbindung besteht, Stichwort Handshake.

```
sudo wg-quick down wg0
```

beendet die Verbindung. Hat alles geklappt, richten wir wie zuvor nun auch auf der Node einen Wireguard Dienst ein und starten diesen. 

```
sudo systemctl enable wg-quick@wg0.service
sudo systemctl start wg-quick@wg0.service
sudo systemctl status wg-quick@wg0.service
```

## Node Verbindung 

Auch wenn Port 9735 oder 9736 der Clearnet VPS IP nun auf eure Node zeigt, müssen die entsprechenden Settings innerhalb der jeweiligen LN-Implentierung noch eingetragen werden, um die Node im Hybrid Modus zu fahren.

Im Raspiblitzmenü unter System findet ihr die entsprechenden Konfigurationsdateien, die ihr wie folgt bearbeiten müsst.

LND

```
externalip=PUBLIC_IP:9735
nat=false

tor.active=true
tor.v3=true
tor.streamisolation=false
tor.skip-proxy-for-clearnet-targets=true
```

CLN

```
bind-addr=0.0.0.0:9736
addr=statictor:127.0.0.1:9051/torport=9736
always-use-proxy=false
announce-addr=PUBLIC_IP:9736
```

In beiden Fällen solltet ihr checken, ob gewisse Einträge nicht bereits vorhanden sind und geändert werden müssen.

Nun müsst ihr beim Speichern der Datei den entsprechenden Service neu starten.

Das war's. Eure Nodes und Dienste sollten nun unter der entsprechenden IP erreichbar sein


Wenn euch das Tutorial gefallen hat und alles funktioniert, wie es soll, freue ich mich, wenn ihr meinen LNurlp-Link mal ausprobiert ;)

[<img src=https://raw.githubusercontent.com/Surenic/oracle-vps-wireguard-server-LN/main/QR.png width="200" height="200">](https://lnbits.surenic.net/lnurlp/2)

Folgt mir auf Twitter!

[<img src=https://upload.wikimedia.org/wikipedia/commons/4/4f/Twitter-logo.svg width="50" height="50">](https://twitter.com/surenic)

Ansonsten freue ich mich auf Verbesserungen, Anregungen und ähnliches
