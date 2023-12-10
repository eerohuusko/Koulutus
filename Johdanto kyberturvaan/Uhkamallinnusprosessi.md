Uhkamallinnusprosessi ja STRIDE IoT-järjestelmän testausmenetelmänä
===

Uhkamalli on prosessi, joka tarkistaa minkä tahansa verkkopohjaisen järjestelmän turvallisuuden, tunnistaa ongelma-alueet ja määrittää kuhunkin alueeseen liittyvän riskin. Uhkamallinnus on käyttökelpoinen IoT-järjestelmän suunnittelu- ja mallin- nusvaihessa. Mallinnuksessa tunnistetaan haavoittuvuuksia ja pyritään poistamaan niitä ennen kuin yhtään koodiriviä on kirjoitettu. Prosessissa on tyypillisesti kuusi vaihetta:
1. Tunnistetaan kaikki laitteen omaisuudet,
2. Visualisoidaan laitteen arkkitehtuuri,
3. Puretaan IoT-laite,
4. Tunnistetaan uhat STRIDE-mallin avulla,
5. Dokumentoidaan löydetyt tietoturvauhkat ja
6. Arvioidaan löydetyt uhkat DREAD-mallin avulla.

## STRIDE
STRIDE on malli uhkista, jota voidaan käyttää puitteena turvallisen sovellussuunnittelun varmistamisessa. STRIDE on lyhenne, joka tarkoittaa:

* Spoofing Identity - Huijaus henkilöllisyydestä on uhka,jossa hyökkääjä käyttää uhrin henkilöllisyyttä. Hyökkääjä ottaa esimerkiksi järjestelmänvalvojan identiteetin.
* Tampering With Data - Tietojen peukalointi on uhka, jossa hyökkääjä muuttaa järjestelmän tietoja. Esimerkiksi hyökkääjä muuttaa tilin saldoa tai käyttään tunnistautumistietoja.
* Repudiation Threats - Kieltäminen on uhka,jossa hyökkääjä poistaa tai muuttaa tapahtuma- tai kirjautumistietoja yrittääkseen kumota niiden koskaan tapahtuneen.
* Information Disclosure - Tietojen paljastaminen on uhka, jossa arkaluontoisia tietoja varastetaan ja myydään voiton saamiseksi.
* Denial of Service - Palvelunesto on uhka, jossa järjestelmän resurssit ylikuormitetaan. Hyökkääjä on esimerkiksi voinut saada automaattiset palvelimet tai bot-verkot kirjautumaan jatkuvasti uhrijärjestelmään ja katkaisemaan kaikki yhteydet, jotta lailliset käyttäjät eivät pääse sisään.
* Elevation of Privileges - Oikeuksien korottamisen on uhka, jossa järjestelmän valtuutettu tai luvaton käyttäjä voi päästä käsiksi muihin tietoihin, joita heillä ei ole valtuuksia nähdä.

## DREAD
Uhkien arviointimalli DREAD (**Damage potential, Reproducibility, Exploitability, Affected Users, Discoverability**) on menetelmä, jonka Microsoft on kehittänyt tietoturvariskin laskemiseksi. Alla olevassa kuvassa on DREAD-menetelmän luokat, joista jokainen arvioidaan asteikolla 0-10. 
Menetelmä perustuu viiden luokan arvojen keskiarvoon, jota käytetään priorisoitaessa käsiteltävät tietoturvauhkat.

![](https://gitlab.dclabra.fi/wiki/uploads/upload_dc479ca3ce6b8514a32dfe3161a18f3d.png)

Keskiarvo koostuu tietoturvariskin tai uhkan todennäköisyyden arvioinnista, uhkan vakavuuden lukuarvosta, uhkan toteutuessa arvioidaan luku, jolla kuvataan vaikutusta ja uhkan aiheuttamaa vahinkoa, uhkan löydettävyydelle annetaan myös arvo ja viimeiseksi arvioidaan uhkan toistettavuus.

## IoT-järjestelmän verkkoliikenteen analysointi testausmenetelmänä
Internetissä laitteiden välinen kommunikaatio tapahtuu tietoliikennepakettien välityksellä. Yleisellä tasolla määriteltynä tietoliikennepaketit ovat käytettävästä pro- tokollasta riippuen tietyn mittaisia paketteja, jotka tyypillisesti sisältävät otsikon ja kuljetettavan tietosisällön. Verkkoliikenteen analysoinnissa tarkkaillaan tietoliikennepaketteja, jolloin niistä voidaan kerätä paljon erilaista tietoa. 

Kiinnostuksen kohteena ovat esimerkiksi vastaanottajan ja lähettäjän IP-osoitteet, käytetty protokolla ja lähetetyn paketin tietosisältö. Sisällön avaaminen on helppoa, jos salausta ei ole käytetty. Pakettien tarkkaileminen mahdollistaa näin ollen verkkoliikenteen tarkan analysoimisen ja myöskin valvomisen verkon luvattomalta käytöltä. 

Tietoliikennettä ja IoT -järjestelmässä käytettyjen protokollien toimintaa voi seurata useilla erilaisissa analysointiohjelmilla. Ohjelmien avulla voi kuunnella ja kaapata tietoliikenneverkossa kulkevia paketteja. 

Pakettien kaappaamisella (engl. packet capture) voidaan analysoida tarkemmin datapakettien sisältöä. Pakettien kaappaamisella voidaan varmistua myös yksityisyyden suojaan kuuluvien tietojen suojauksesta. 

Pakettien tarkkaileminen on yleistä tietoliikenneverkkoihin kohdistuvissa hyökkäyksissä, mutta paketteja tarkkailemalla voidaan myös analysoida IoT-laitteisiin kohdistuvien palvelunestohyökkäysten uhkaa. 

Verkkoliikenteen analysointi on IoT- kuluttajalaitteissa tärkeää, koska laitteiden on tarkoitus kytkeytyä Internet-verkkoon ja laitteisiin pitää pystyä muodostamaan etäyhteys. Tästä syystä tällaiset laitteet ovat haavoittuvaisia myös ulkopuolelta tuleviin laittomiin yhdistämisyrityksiin. 

Haavoittumisen sisältävässä laitteessa voi olla esimerkiksi Telnet-etäyhteys tai kovakoodattu käyttäjätunnus ja salasana, jolloin yhteyden muodostaminen onnistuu ilman tunnistautumista.
Tietoliikenteen seuraamiseen on saatavilla useita valmiita ohjelmia (Wireshark).