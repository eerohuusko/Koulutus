Kyberturva IoT laitteissa - Shodan hakukoneen käyttö
===

Internet on läsnä kaikkialla ja on olennainen osa verkottunutta yhteiskuntaamme. Internettiin on yhdistetty yli 75 miljardia laitetta, kuten  palvelimia, web-kameroita, reitittimiä ja vaikkapa teollisuuden ohjausjärjestelmiä. Liitettävyys internetiin tarjoaa uudenlaista käytettävyyttä, uusia ominaisuuksia, mutta samalla se tuo mukanaan myös uusia tietoturvariskejä. 

On erittäin tärkeää tunnistaa Internetin aiheuttamat turvallisuusriskit. IoT-laitteiden suosio on kasvanut viime vuosina. Tilastot osoittavat, että pelkästään  IoT-verkkolaitteiden määrä ylitti 35 miljardia vuonna 2022. Tämä nopea käyttöönotto teki näistä laitteista
ilmeisen kohteen pahantahtoisille toimijoille. Hyökkäykset, kuten bottiverkot ja haittaohjelmien lisääminen, alkavat yleensä **Tiedusteluvaiheella**, jossa kerätään tietoa kohteen IoT-laitteesta ennen löydetyn haavoittuvuuden hyödyntämistä.

**Shodan (Sentient Hyper-Optimised Data Access Network)** on yksi hakukoneista, joka seuloo Internetin kerroksia ja pyrkii paljastamaan piilotettujen ja julkisesti saatavilla olevien laitteiden maailman.

Shodan (Sentient Hyper-Optimised Data Access Network) on hakukone, joka on suunniteltu kartoittamaan ja keräämään tietoa Internetiin liitetyistä laitteista ja järjestelmistä. Shodania kutsutaan joskus asioiden internetin (IoT) hakukoneeksi. Ohjelmiston sovelluksia ovat markkinatutkimukset, haavoittuvuusanalyysit ja penetraatiotestaukset sekä hakkerointi.

John Matherly keksi idean etsiä Internetiin kytkettyjä laitteita vuonna 2003 ja lanseerasi Shodanin vuonna 2009. Nopeasti kävi ilmi, että hakkerit voivat käyttää työkalua haavoittuvien järjestelmien löytämiseen ja  monet  Iot laitteet ja IoT järjestelmät kaikkialla maailmassa olivat helposti saatavilla, jotka ovat samalla riittämättömästi suojattu laitteistohyökkäyksiltä, teollisuusvakoilulta ja sabotaasilta.

Shodan on nimetty System Shock -nimisen videopelisarjan hahmosta.

Shodan mahdollistaa Internetiin kulloinkin yhteydessä olevien laitteiden, näiden laitteiden sijainnin ja niiden nykyisten käyttäjien havaitsemisen. Tällaisia laitteita voi olla melkein missä tahansa järjestelmässä, mukaan lukien yritysverkot, valvontakamerat, teollisuusohjausjärjestelmät (ICS) ja älykodit. Shodan yrittää napata järjestelmän bannerin suoraan keräämällä tiedot siihen liittyvän palvelimen porttien kautta. Bannerin tarttuminen on keskeinen vaihe tunkeutumistestauksessa, koska se auttaa tunnistamaan haavoittuvat järjestelmät. Shodan etsii myös vastaavia hyötyjä hakualustan hyödyntämisosiossa.

Shodan tukee Boolen operaattoreita ja tarjoaa suodattimia haun tehokkuuden parantamiseksi. Hakukone tarjoaa 50 tulosta ilmaiseksi ja tarjoaa maksullisia tilauksia laajempia tuloksia varten.

## Miten Shodan-haut eroavat muista hakukoneista?

Shodan tutkii ja indeksoi metatietoja ja bannereita useista Internetiin yhdistetyistä laitteista sen sijaan, että indeksoisi verkkosivuja. 

Shodanin avulla hakkerit voivat saada tärkeitä tietoja yhdistettyjen laitteiden laajasta ekosysteemistä keräämällä tietoa avoimista porteista, laitetyypeistä, maantieteellisistä sijainneista ja jopa mahdollisista haavoittuvuuksista. 

Shodan on myös tärkeä työkalu kyberturvallisuuden asiantuntijoille ja tutkijoille. 

Se tarjoaa meille ainutlaatuisen näkökulman, jonka avulla voidaan löytää mahdollisia turvallisuusongelmia, tutkia julkisen näkyvyyden ulottuvuutta ja saada parempi käsitys globaalista IoT-ekosysteemistä, jossa myös sijaitsevat vaikkapa analysoitavan yrityksen verkossa olevat laitteet.

## Tiedustelu (Reconnaissance)

Tiedusteluhyökkäykset on suunniteltu keräämään tietoa mahdollisista kohteista. Tiedustelun tarkoitus on
kerää hyökkäystä edeltävää tietoa verkoista, verkon aktiivisista isännistä ja palveluista. Lisäksi tiedusteluhyökkäykset auttavat hyökkääjää kohdentamaan mahdollisen hyökkäyksen tarkemmin kohdeverkkoon ja verkon IP-osoiteavaruuteen.
Tiedusteluhyökkäyksissä kerättyjä tietoja käytetään hyväksikäytettävien kohteiden tunnistamiseen ja kohteissa olevien haavoittuvuuksien analysointiin, joita voidaan käyttää tulevissa kyberhyökkäyksissä. Tiedustelu on aina ns. aloitusaskel ja sitä seuraa yleensä aseistaminen, toimittaminen ja hyödyntämisvaiheet (weaponization, delivery, and exploitation steps).

## Open Source Intelligence (OSINT)

Shodan on yksi eniten käytetty OSINT verkkopalveluita skannaava palvelu.

OSINT on tiedonkeruuprosessi kohteesta olematta suoraan vuorovaikutuksessa kohteen kanssa. Tämä hyökkäys tapahtuu siten, että hyökkääjä kerää tietoja kohteesta julkisesti saatavilla olevista tiedoista kuten DNS (Domain Name System) -tietueet, verkkotunnuksen rekisteröintitiedot ja myöskin avoimesta sosiaalisesta mediasta. 

Erityisesti DNS-tiedustelu voi paljastaa verkkoinfrastruktuurin hälyttämättä uhreja. Monet organisaatiot eivät valvo DNS-liikennettä tai rajoittavat vain valvontaa vyöhykkeiden siirtoyrityksiin. 



Katso videolinkki Shodanista: https://youtu.be/T-9UvZ-l-tE


## Shodan-haut on jaettu kahteen osaan:

Hakujen suorittamiseen on käytetty Basic-jäsenyyttä, jossa Query and Scan luottoraja on 100 yksikköä ( kuukaudessa) ja yhteensä 16 IP:tä voidaan seurata.s

Käytettävissä olevissa hakusuodattimissa on joitain rajoituksia: Tag- ja Vuln-suodattimet eivät ole käytettävissä tässä Shodan-basic versiossa.



## Shodan käyttöönotto

1. Web-näkymä: https://www.shodan.io/

Aluksi kannattaa luoda tili. Shodan hyväksyy esim. gmail-kirjautumisen.

Shodan dasboard näkymä aukeaa ainakin clikkaamalla ```<ACCOUNT> ```"nappulaa" 

https://www.shodan.io/dashboard

![](https://gitlab.dclabra.fi/wiki/uploads/upload_a836dceea208be677f34694033ad172b.png)

## Command Line Interface (CLI)

The command-line interface (CLI) for Shodan is provided alongside the Python library. This means that you need to have Python installed on your computer in order to use the Shodan 

To start with the CLI-based searches, first, we need to install the Shodan CLI (Command Line Interface) on the system, whether it is Windows, Linux or MAC OS.

* Install the Python: on the system from the official Python website (https://www.python.org/downloads/).
* Shodan Account: If you don’t have one already, sign up for a Shodan account at https://www.shodan.io/. You will need an API key to use the Shodan CLI. Signing up for an account is FREE.
* Install Shodan Module: Open your terminal or command prompt and run the following command to install the Shodan module using pip, the Python package manager:

```pip install shodan```

* API Key Configuration: Once the Shodan module is installed, you need to configure your API key. Run the following command in the terminal: 

```shodan init YOUR_API_KEY.```

![](https://gitlab.dclabra.fi/wiki/uploads/upload_ef1db2a5e49b87173de20d43dba6a432.png)


Replace YOUR_API_KEY with the actual API key you obtained from your Shodan account.
* Verify Installation: To verify that the installation was successful and the API key is correctly configured, you can run a simple command:

```shodan info```

This command will display information about your Shodan account.


## Shodan käyttö haavoittuvuustestauksessa ja tiedustelussa (Vulneability testing and Network reconnaissance)

Blue teamin -hakkereiden näkökulmasta Internetin paljastamat IP-alueet voivat olla suuri turvallisuusongelma. Vanhentuneet sertifikaatit, tunnetut haavoittuvuudet ja avoimet palvelut ovat kaikki mahdollisia tietoturvariskejä, joita Blue-tiimien tulee etsiä arvioidessaan vaarassa olevia IP-alueita.

Ensimmäiseksi tulee selvittää tutkittavan organisaation IP-alueet. Tämä tehdään organisaation IP-alueisiin perustuvilla perushakuoperaatioilla, joilla etsitään Internetin kautta paljastuvaa sisältöä.

## Blue-team hakkereiden Shodan steppilista:

Haku 1: Etsitään organisaation IP-alueilta näkyvät palvelut osoite ja porttitiedoilla.

Shodan haavoittuvuuden arviointiin (vulnerability assessment, VA) / läpäisytestaukseen (penetration testing, PT). 

Shodan voi olla erittäin hyödyllinen suoritettaessa VA tai PT tietyssä verkossa tai isännässä. Jos esimerkiksi isäntä (host) xyz.com käyttää palvelinta ja meidän on löydettävä haavoittuva palvelu, esimerkiksi sähköpostipalvelin, FTP tai reititin, se voidaan tunnistaa isäntänimen kanssa. Tässä skenaariossa käytetään seuraavaa hakumerkkijonoa.

```
Käyttö: palvelun nimi isäntänimi: host.com

Esimerkki: proftpd-isäntänimi: xyz.com

Etsi laitteita, jotka vastaavat isäntänimeä.
server: "gws" hostname:"google.com"
````

Esimerkkien merkkijonot näyttävät proftpd-bannerin, jos isäntä xyz.com käyttää palvelua.

Haku 2. Shodanin perussuodattimet

Shodanissa on useita tehokkaita mutta helppokäyttöisiä suodattimia, jotka osoittautuvat käteviksi VA/PT-harjoituksissa. Suodattimien käyttö on yleensä muotoa filter:value. Joitakin yleisimpiä perussuodattimia, joita voit käyttää Shodanissa, ovat seuraavat.

1. Maa: Maasuodattimen avulla käyttäjät voivat etsiä tietokoneita, jotka käyttävät palveluja tietyssä maassa. Maakoodi määritetään kaksikirjaimisena sanana.

```
Käyttö: Cisco maa: IN (hakee Cisco-laitteita tietystä maasta. Tässä tapauksessa se on Intia).
```

2. Isäntänimi: Tämän Shodanin hyödyllisen vaihtoehdon avulla voit löytää tietyn palvelun tai palvelun, joka toimii tietyissä isännissä tai toimialueissa.
```
Käyttö: "Server:IIS" isäntänimi: verkkotunnuksen nimi

Isäntänimi: verkkotunnuksen nimi
````

3. Verkko: Tätä suodatinta käytetään tietyn IP-osoitteen tai aliverkkoalueen skannaamiseen. Palvelun nimi voidaan myös lisätä IP-osoitteen tai aliverkon kanssa.

```
Käyttö: IP-osoitteen skannaukseen: verkko: 198.162.1.1 (mikä tahansa IP)

Aliverkon skannaus: verkko: 198.162.1.1/24
```

4. Portti: Tämän suodattimen avulla voit skannata tietyn palvelun. Esimerkiksi FTP (21), HTTP (80).

```
Käyttö: Huoltoportin (IIS) numero

Esimerkki: IIS-portti: 80
```

5. Käyttöjärjestelmä (OS): Tämä Shodan-suodatin auttaa sinua tunnistamaan palvelun, jolla on vaadittu käyttöjärjestelmä. Voit käyttää sitä löytääksesi tietyssä käyttöjärjestelmässä toimivan palvelun.

```
Käyttö: Palvelu: Käyttöjärjestelmä: Käyttöjärjestelmän nimi

Esimerkki: IIS "OS: OSName"
````

6. After/ennen: Tämä vaihtoehto auttaa tai palauttaa kyselyn, muutettuna tai muuttumattomana ennen.

```
Esimerkki: apache jälkeen: 22/03/2010 ennen: 4/6/2010

Esimerkki: apache-maa: CH jälkeen:22/03/2010 ennen: 4/6/2010
````

7. Citrix:

```
Find Citrix Gateway.
title:"citrix gateway"
```

8. Wifi Passwords:

Helps to find the cleartext wifi passwords in Shodan.
```
html:"def_wirelesspassword"
```
9. Mongo DB servers:

It may give info about mongo db servers and dashboard
```
"MongoDB Server Information" port:27017 -authentication

```
Jos kohde on reititin, oletussalasanoilla voidaan yrittää päästä käsiksi. Netin syövereistä löytyy runsaasti oletussalasanalistoja, joita voi hyödyntää tietoturva-aukkojen testaamisessa.

10. Hacked routers:

Routers which got compromised
```
hacked-router-help-sos
````
11. Telnet Access:

NO password required for telnet access.
```
port:23 console gateway
````
11. os:

Find devices based on operating system. 
```
os:"windows 7"
````

12. Server
```
server: nginx server: apache server: microsoft server: cisco-ios
```
13.MySQL
```
"product:MySQL" mysql port:"3306"
````
14.Generic camera search
```
title:camera
````

15.Webcams with screenshots
```
webcam has_screenshot:true
````

16. D-Link webcams
```
"d-Link Internet Camera, 200 OK"
````
17. Chromecasts / Smart TVs
```
"Chromecast:" port:8008
````
18. MQTT Briker
"Generic - standard port for MQTT + MQTT banner / MQTT -> MQ Telemetry Transport"
```
port:1883"MQTT Connection Code" 
```

19. Haussa voidaan etsiä MySQL-palveluita, jotka eivät toimi vakioporteissa 3306 (MySQL-portti) ja haku jättää huomiotta myös portit 80 443 MySql:lle.
 ```
-port:80,443.3306 product:”MySql”
```
20. Lisää hakuoperaattoreita

Verkkosegmentin etsimisen sijaan seuraavassa haussa haetaan organisaation nimeä maan ja kaupungin kanssa. Tuloksina näytettävät kentät ovat IP-osoite, portti, isäntänimi, käyttöjärjestelmä, maa ja kaupunki, rajaus enintään 10 hakutulosta.

```
org:"Amazon" country:FI City:Helsinki --fields ip_str,port,hostnames,os,country,city --limit 10
````




