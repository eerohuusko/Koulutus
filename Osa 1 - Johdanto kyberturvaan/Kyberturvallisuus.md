Kyberturva - Yleiskatsaus haittaohjelma-analyyseihin
===

# Kybersää 2023

Tekniikka&Talous kysyi yrityksiltä muun muassa sitä, onko niillä ollut havaintoja tai kokemuksia vieraan vallan toiminnasta kriittisen infrastruktuurin lähistöllä viime vuosina.

Useimmat kertoivat, ettei niiden kriittisen infran tiluksilla ole liikkunut vieraan vallan edustajia. Ainakaan yhtiöt eivät sitä myönnä. Jokunen myös totesi, ettei halua kertoa asiasta.

Moni ei myöntänyt ryhtyneensä ylimääräisiin turvatoimiin, mutta esimerkiksi verkkoyhtiö Caruna kertoi nostaneensa varautumistaan Ukrainan kriisin seurauksena.

Suur-Savon Sähkön toimitusjohtaja Markus Tykkyläinen kertoi kuitenkin, että yhtiön kriittisten kohteiden ympärillä on ollut ulkomaisilla rekisterikilvillä varustettujen ajoneuvojen liikettä aiemmasta poikkeavalla tavalla.

Tarkemmin hän ei halunnut yksityiskohtia kertoa, mutta Tykkyläisen mukaan monenlaista tekniikkaa havaitsemiseen on nykyään hyvin saatavilla.

Mutta miksi useimmat energiayhtiöt haluavat vaieta asiasta?

Tykkyläisen mukaan yhteiskuntamme on rakennettu rauhanajan tilanteeseen, eikä meillä ole mietitty korostetusti poikkeusolosuhteiden tilanteita.

”Energiainfraa on paljon maan päällä ja heikosti ulkoisilta uhilta suojatuissa rakenteissa. Aihepiiri on herkkä. Energiayhtiöt ovat nostaneet valmiuttaan viimeisen vuoden aikana huomattavasti, mutta rakenteille ja niiden avoimuudelle ei pysty mitään lyhyellä aikavälillä”, hän sanoo.

”Mitään sellaista ei ole tiedossa tai tapahtunut, mikä uhkaisi meidän osaltamme energian huoltovarmuutta.”

Auris Energiasta kerrotaan, että salasanojen ja käyttäjätunnusten kalasteluyrityksistä on tullut arkipäivää.

Mahdolliset hyökkäykset energiainfraa kohtaan huolestuttavat.

”Venäjä ja heidän aggressionsa ovat arvaamattomia”, eräs vastaaja toteaa.

Kyselyhetkellä tilanne vaikutti energiayhtiöissä rauhalliselta, mutta siitä ei ollut takeita, etteikö energia-alan tilanne hankaloituisi uudestaan.

”Sodan aiheuttama energiakriisi on muuttanut toimintaympäristömme määrittelemättömäksi ajaksi”, arvioidaan Helsingin Helenistä.

”Ehkä Venäjän taholta nähdään vielä jokin markkinoita sekoittava yllätys?” Kuopion Energian toimitusjohtaja Esa Lindholm pohti helmikuussa 2023.

## Miten kriittistä infraa vastaan hyökätään?

**Haittaohjelmat (Malware)** viittaavat ohjelmiin, joiden tarkoituksena on vahingoittaa tietokonejärjestelmiä ja verkkoja varastamalla tai väärinkäyttäen luottamuksellisia tietoja ilman lupaa tai rajoittamalla verkon kaistanleveyttä. 

Haittaohjelmien vaara on kasvanut jatkuvasti ja sillä voi olla vaikutusta yksilötasolta myös organisaatiotasolle. Jotta tällaiset ohjelmistot eivät pääse järjestelmiin, suoritetaan kyberturavatestauksessa tai forensiikassa usein haittaohjelmaanalyysi.

Forensikka ja haittaohjelma-analyysi ovat tärkeitä ja kasvava käytöntö kyberturvallisuusalalla. 

## Haittaohjelma (Malware)

Haittaohjelmat on suunniteltu vahingoittamaan tai hyödyntämään tietokoneita ja verkkoja. Haittaohjelmahyökkäykset voivat aiheuttaa merkittäviä vahinkoja organisaatioille ja henkilöille aina arkaluontoisten tietojen varkauksista kriittisten järjestelmien häiriöihin. 

Haittaohjelmat voidaan luokitella neljään luokkaan: virukset, madot, troijalaiset ja kiristysohjelmat.

* **Virukset** ovat ohjelmia, jotka voivat replikoida itsensä saastuttamalla muita tiedostoja tai järjestelmiä. Ne voivat levitä sähköpostin liitteiden, tartunnan saaneiden verkkosivustojen tai tiedostonjakoverkkojen kautta. Kun virus tarttuu järjestelmään, se voi aiheuttaa vahinkoa korruptoimalla tiedostoja tai varastamalla arkaluonteisia tietoja.
* **Madot** muistuttavat viruksia siinä mielessä, että ne voivat replikoida itsensä, mutta ne eivät vaadi isäntätiedostoa. Sen sijaan ne voivat levitä verkoissa tai Internetissä yksinään. Madot voivat aiheuttaa vahinkoa kuluttamalla verkon kaistanleveyttä, kaatumalla järjestelmiin tai varastamalla tietoja.
* **Troijalaiset** ovat ohjelmistosovelluksia, jotka näyttävät olevan luotettavia, mutta sisältävät itse asiassa haitallista koodia. Ne voidaan ladata Internetistä tai levittää sähköpostin liitetiedostoina. Kun troijalainen saastuttaa järjestelmän, se voi antaa hyökkääjille etäkäytön järjestelmään, varastaa arkaluontoisia tietoja tai aiheuttaa muun tyyppistä vahinkoa.
* **Ransomware** on eräänlainen haittaohjelma, joka salaa järjestelmän tiedostoja ja vaatii rahaa vastineeksi salauksen purkuavaimesta. Se voi levitä tartunnan saaneiden sähköpostiliitteiden, saastuneiden verkkosivustojen tai tiedostonjakoverkkojen kautta. Ransomware-ohjelmat voivat aiheuttaa merkittäviä vahinkoja salaamalla tärkeitä tiedostoja ja tekemällä niistä käyttökelvottomia.


## Python haittaohjelmien analysointiin

Python on suosittu ohjelmointikieli haittaohjelmien analyytikoiden keskuudessa monipuolisuutensa ja helppokäyttöisyytensä ansiosta. Pythonin laaja moduuli- ja työkalukirjasto voi virtaviivaistaa haittaohjelmanäytteiden analysointia ja niiden käyttäytymisen tunnistamista.

Pythonin automatisointiominaisuudet ovat hyödyllisiä myös tehtävien ja prosessien automatisoinnissa haittaohjelmien analysoinnin työnkulussa, mikä tekee prosessista tehokkaamman ja virtaviivaisemman. 

Yksi Pythonin käytön haittaohjelmien analysoinnissa merkittävistä eduista on kirjastojen ja työkalujen saatavuus tehtäviin, kuten purkamiseen tai käänteiseen suunnitteluun.

Näiden työkalujen avulla analyytikot voivat poimia ja analysoida haittaohjelmanäytteiden taustalla olevan koodin, mikä auttaa heitä ymmärtämään, miten haittaohjelma toimii ja mitä se tekee.

Lisäksi Pythonin korkean tason syntaksi ja dynaaminen koodi kirjoittaa tiiviin koodin kirjoittamisen, joka on samalla helppo ymmärtää ja ylläpitää. 

Python sopii hyvin eri alustoille yhteensopivuutensa asnsiosta. Kyberturva-analyytikot voivat käyttää Pythonia monissa käyttöjärjestelmissä ja laitteissa. Kaiken kaikkiaan Pythonin joustavuus, helppokäyttöisyys ja laaja moduulikirjasto tekevät siitä ihanteellisen valinnan haittaohjelmanäytteiden analysointiin ja niiden käyttäytymisen ymmärtämiseen.

## Työkaluja ja kirjastoja haittaohjelmien analysointiin Pythonilla

Python tarjoaa laajan valikoiman työkaluja ja kirjastoja, joita voidaan käyttää haittaohjelmien analysointiin. Alla on valikoima suosituimmista:

## Pyew

**Pyew** on Python-pohjainen komentorivityökalu, jonka avulla käyttäjät voivat suorittaa rikosteknisen analyysin haittaohjelmanäytteille. Siinä on useita ominaisuuksia, kuten kyky tunnistaa tiedostotyypit, muuntaa tiedostoja ja purkaa. 

Pyew voi poimia tietoja tiedoston otsikoista, osioista ja tuonnista sekä sen yleisestä rakenteesta ja sisällöstä. Pyew voi myös analysoida tiedoston koodiosan ja tunnistaa epäilyttävän toiminnan, kuten pakkaajien tai hämärtämistekniikoiden olemassaolon. 

Pyew Python -kirjastoa voidaan käyttää automatisoimaan Portable Executable -tiedostojen analysointia ja poimimaan tietoja haittaohjelman toiminnasta.

[Pyew](https://directory.fsf.org/wiki/Pyew)

### Esimerkki

Tässä kuvataan esimerkki haittaohjelmaanalyysin suorittamisesta pyew-kirjaston avulla.

## Scapy

**Scapy** on tehokas Python-paketti pakettien muokkaamiseen ja verkkoanalyysiin. 

Se mahdollistaa verkkopakettien luomisen ja manipuloinnin sekä verkkoliikenteen analysoinnin. 

Scapyn avulla voidaan tunnistaa haittaohjelmien synnyttämä epäilyttävä verkkoliikenne, kuten yhteydet komento- ja ohjauspalvelimiin tai tietojen suodattaminen. 

Scapy Python -kirjastoa voidaan myös käyttää automatisoimaan verkkoliikenteen analysointia ja poimimaan tietoa haittaohjelman käyttäytymisestä.

[Scapy net](https://scapy.net/)

[Scapy in 0x30 Minutes](https://guedou.github.io/talks/2022_GreHack/Scapy%20in%200x30%20minutes.slides.html#/)


## Yara

Yara on tehokas avoimen lähdekoodin työkalu, jonka avulla voidaan luoda sääntöjä haittaohjelmien tunnistamiseksi tiettyjen ominaisuuksien, kuten tiedostonimien, hajautusten ja merkkijonojen, perusteella. 

Yara-säännöt voidaan kirjoittaa yksinkertaisella ja joustavalla syntaksilla, jota on helppo ymmärtää ja muokata. 

Yara Python -kirjasto mahdollistaa Yara-sääntöjen integroinnin Python-skripteihin automaattista haittaohjelmaanalyysiä varten. 

Yara Python -kirjastoa voidaan käyttää myös Yara-sääntöjen mukaisten hakemistojen tai tiedostojen tarkistamiseen.

[Using YARA from Python](https://yara.readthedocs.io/en/stable/yarapython.html)
