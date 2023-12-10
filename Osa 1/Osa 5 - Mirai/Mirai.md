Kyberturva - Mirai botnet
===

# Mirai-botnet

## Johdanto

Mirai (未来) on haittaohjelma, joka on suunniteltu suuren mittakaavan botnet-verkkojen rakentamiseen IoT-laitteille. Botin ja siihen liittyvät ohjelmat loi Anna-senpai, joka löydettiin ensin ja MalwareMustDie tutki sen elokuun 2016 lopussa. 
Vastauksena blogikirjoitukseensa, kuukautta myöhemmin Anna-sepai julkaisi lähteet ja oppaan siitä, miten rakentaa ja ylläpitää botnet-verkkoa, huomauttaen samalla analyysivirheistä ja nöyryyttäen unixfreik-viestin kirjoittajaa.

Mirai-bot etsii verkosta laitteita, joissa telnet/ssh-portti on auki, ja järsii auki useita yleisimpiä oletussalasanoja. Koska IoT-laitteiden käyttäjät
eivät useinkaan välitä paljon turvallisuudestaan, suuri osa heistä on alttiina hyökkäyksille. Ja suuren IoT-laitteiden määrän vuoksi Mirai-botnet
voi kasvattaa satojatuhansia isäntiä.

Kun Mirai on tartuttanut isäntäkoneen, se päivittää (koventaa) salasanat suojatakseen itseään muita robotteja tai haittaohjelmia vastaan. Mirai ei asenna itseään kohdelaitteeseen, vaan pysyy vain RAM-muistissa.
Tämä käyttäytyminen oli este tutkimuksille, koska ainoa tapa saada binaari oli poistaa se RAM-muistista.

Tällä hetkellä suurin osa IoT-bottiverkoista on johdettu Mirai-versioista, niiden työnkulku on periaatteessa sama kuin alkuperäisessä Miraissa. 
Harjoituksessa käytetään Miraita esimerkkinä haitallisen verkkoliikenteen analysointiin ja samalla perehdytään botnet-hyökkäyksen periaatteisiin. 

Kuvassa 1 esitetään Mirain tartunta- ja hyökkäysprosessia.
![](https://gitlab.dclabra.fi/wiki/uploads/upload_dc324e810dcfa4964fcede45bcb0b835.png)
Kuva 1. Mirai botnet hyökkäysprosessi.

1. Botti käyttää Telnetiä tai SSH:ta etsiäkseen IoT-laitteita Internetissä ja murtaa raa'alla voimalla heikkoja salasanoja. 

2. Kirjautumistiedot, jotka sisältävät käyttäjätunnuksen, salasanan, IP osoitteen ja portin numeron haavoittuvilta laitteilta, välitetään raporttipalvelimelle analysoitavaksi. 
3. Raporttipalvelin jakaa haavoittuvien laitteiden tiedot ladattavaksi latauspalvelimelle. 
4. Latauspalvelimet käyttävät näitä tietoja hakeakseen latausapuohjelman yhden palvelimen kautta kolmella menetelmällä: 
    * **echo,**
    * **wget** tai 
    * **Trivial File Transfer Protocol (TFTP)**

Lopuksi saastuneella laitteella Loader lataa haitallisen Bot-ohjelman Mirai-latauspalvelimelta. 

5. Kun laite suorittaa haittaohjelman, siitä tulee uusi botti. Toisin kuin tavalliset botnetit, Mirain tartuntaprosessi ei voi olla vain hyökkääjän palvelimen käynnistämä, vaan se voi myös olla tartunnan saaneiden laitteiden käynnistämä
6. Uusi Botti alkaa heti vastaanottaan komentoja komento- ja ohjauspalvelimelta (CnC, Command and Control Serveri). 
7. Bottiohjelma tartunnan saaneessa laitteessa alkaa skannaamaan Internetissä olevia laitteita satunnaisen strategian avulla. 
8. Kun IoT-laite on saanut  botnettartunnan, Bot-tartunnan saaneen laitteen moduuli alkaa tarkistamaan muita IoT-laitteita tai Botti voidaan aktivoida suorittamaan DDOS-hyökkäystä.

## Hyökkäystyypit

  0. UDP flood `ATK_VEC_UDP`
  1. Valve Source Engine query flood `ATK_VEC_VSE`
  2. DNS water torture `ATK_VEC_DNS`
  3. SYN flood `ATK_VEC_SYN`
  4. ACK flood `ATK_VEC_ACK`
  5. ACK flood to bypass mitigation devices `ATK_VEC_STOMP`
  6. GRE IP flood `ATK_VEC_GREIP`
  7. GRE Ethernet flood `ATK_VEC_GREIP`
  8. Proxy knockback connection `ATK_VEC_PROXY`
  9. Plain UDP flood optimized for speed `ATK_VEC_UDP_PLAIN`
  10. HTTP layer 7 flood `ATK_VEC_HTTP`

# Mirain lähdekoodi
Mirain lähdekoodi voidaan jakaa seuraaviin kolmeen moduuliin:

* **Bottimoduuli**: Moduuli on kirjoitettu C-ohjelmointikielellä. Kun Botti on käynnistetty, Mirai poistaa exe-tiedostonsa ja jatkaa toimintaansa vain RAM-muistilla. Tämä Mirain pääohjelma, joka toimii tartunnan saaneessa laitteessa, vastaanottaa hyökkäyskomennon annettu CnCs-palvelimelta. Päämoduulin lisäksi siinä on kolme alimoduulia, joilla on seuraavat tehtävät:

– **Attack**: Hyökkäysmoduuli voi rakentaa kymmenen erilaista hyökkäysmenetelmää kymmenestä eri hyökkäysmenetelmätoiminasta.
Kun moduuli vastaanottaa hyökkäyskäskyn, moduuli päättää, mikä hyökkäys aloitetaan.

– **Skanneri**: Skannerimoduuli skannaa jatkuvasti satunnaisesti luotuja IP-laitteita ja pyrjii tarkastamaan mahdolliset haavoittuvat IoT-laitteet Telnetin kautta. Käyttäjätunnukset
ja salasanat poimitaan taulukosta, joka sisältää yleisimmät tehdasasetetut oletusyhdistelmät. Jos telnet onnistuu, skannerimoduuli lähettää löytämänsä laitteiden käyttäjätunnuksia ja salasanoja raporttipalvelimille.

– **Killer**: Killer-moduuli on käynnissä taustalla estääkseen Miraita ns. deletoitumasta. Ensinnäkin Killer sulkee muiden ohjelmien käytössä olevia portteja (Telnet (23), SSH (22) ja HTTP (80)) ja uudelleen palvelee näitä portteja, mutta nyt mahdollistaakseen haitallisen liikenteen. 
Toinen toiminto on poistaa jokin tietty tiedosto ja tappaa tiedostoa käyttävä prosessi Mirai-monopolin saavuttamiseksi. Killer toiminnon tarkoitus on maksimoida järjestelmäresurssien hallittavuus usein rajallisissa IoT-laitteissa.

* **Command-and Control (CNC) -moduuli**: CNC-moduuli on kirjoitettu GO-kielellä. Se hallitsee tartunnan saaneita laitteita ja lähettää DDoS-hyökkäyksiä zombie-asiakkaille. 

Jokainen kahdesta alatilistä (Admin ja User) pystyvät suorittamaan eri toimintatasoja hyökkäykseen käytetyn portin mukaan.
– **Järjestelmänvalvoja (Admin)**: Järjestelmänvalvojalla on korkein etuoikeus. Se voi lisätä uusia käyttäjiä (tiliä).
järjestelmään, raportoi saatavilla olevasta zombies-asiakkaasta CnC-palvelimelle ja ajoittaa uusia hyökkäyksiä.
– **Käyttäjä (User)**: Kun asiakkaat ostavat palveluja hyökkääjiltä Internetin kautta tai darknetistä, he saavat käyttäjätilin. 
Tämän tilin aktivoinnilla voidaan käynnistää rajoitettuja hyökkäyksiä ja sen oikeuksia rajoittaa järjestelmänvalvoja. 
Yleensä hinta ratkaisee esim. sen kuinka paljon hyökkäykseen valjastetaan haavoittuvua IoT-laitteita ja kuinka moneen kohteeseen DDOS-hyökkäys kohdennetaan.
 
* **Loader-moduuli:** Latausmoduuli luo palvelimen hyötykuormien lataamista varten wget, echo tai TFTP busyboxista. Sen jälkeen siitä tulee raportointipalvelin ja vastaanottaa tietoa haavoittuvista IoT-laitteista.

Mirai suodattaa muutamien yritysten ja laitoste IP-osoitteet kuten General Electric, Hewlett-Packard, Yhdysvaltain kansallinen postipalvelu ja puolustusministeriö ei-toivottujen infektioiden estämiseksi. Mutta toki tuo on kierrettävissä, koska Mirai-lähdekoodi on vapaasti saatavilla.

Mirai sisältää melkoisen määrän default username ja salasanapareja. Alla muutama esimerkki:
```
add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x41\x11\x17\x13\x13", 10);
// root/xc3511
add_auth_entry("\x50\x4D\x4D\x56", "\x54\x4B\x58\x5A\x54", 9);
// root/vizxv
add_auth_entry("\x50\x4D\x4D\x56", "\x43\x46\x4F\x4B\x4C", 8);
// root/admin
add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C", 7);
// admin/admin
add_auth_entry("\x50\x4D\x4D\x56", "\x1A\x1A\x1A\x1A\x1A\x1A", 6);
// root/888888
````

# IoT design and defence

1. In the first stage, the attacker uses port scanning tool to find an IoT device which is exposed to the internet. The protocols SSH (port 22), Telnet (port 23) and HTTP/HTTPS (Port 80/443) become the breakthrough points for botnet to infect equipment.
2. In the second stage, the bot continues to penetrate the terminal and discover whether weak passwords are used in the device. Because of user negligence, the username/password may not have changed since device was manufactured, which enables the bot to crack the device using brute force dictionary attack.
3. In the third stage, the terminal becomes a part of the botnet controlled by the attacker, receiving instructions from command and control (CnC) server to launch at attack.

# Protection against port scanning

Port scanning is an important step for the attacker to collect information about the target. 
Usually, the ports of the target host are scanned to determine which ports are open.
Attackers can guess the services enabled by the target host from the open ports, and then find possible vulnerabilities in the target host. 
Common port scanning methods include full TCP connection scanning, SYN scanning, ACK scanning, and UDP scanning. 
The botnet viruses often use SYN scanning method when scanning the available ports of the device.

![](https://gitlab.dclabra.fi/wiki/uploads/upload_81fa0eae8d062c1b6dfc7529e9b0f729.png)
Picture 2. SYN Flood Attack

1. The hostile client will send a connection request synchronization (SYN) packet to the port of server, as if to establish a three-way handshake to the server.

2. The server will reply to the scanning host with SYN-ACK confirmation packet.

3. After hostile client receives the confirmation packet, it will keep slient instead of an acknowledgment (ACK) response. The hostile client could also spoof the source IP address in step (1) in which case the server sends the SYN-ACK to a fake IP address.

Source: Thewindowsclub, 2020

