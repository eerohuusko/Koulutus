Mikä on Shodan? 
===

Shodan on tietoturva-aukkoihin ja esineiden internetin laitteisiin erikoistunut hakukone. Oikeissa käsissä se parantaa kyberturvallisuutta, mutta mustahattuisen hakkerin työkaluna Shodan on kuin pääsylippu netin pimeälle puolelle.

![](https://gitlab.dclabra.fi/wiki/uploads/upload_3e088eb643c64c9ef9bd280db2751dd8.png)

Kyberturvallisuuden rocktähdeksi kutsuttu John Matherly avasi Shodan-hakukoneen vuonna 2009. Nimi Shodan lainattiin kyberpunk-henkisestä tietokonepelistä, jossa on vastustajana samanniminen tekoäly.

Siinä missä tavallinen hakukone etsii web-sivuja niiden sisältämien sanojen perusteella, Shodania kiinnostaa esimerkiksi protokollatason liikenne.

Kun nettiin kytkettyyn laitteeseen otetaan yhteys, se vastaa protokollan mukaisesti lähettämällä tervehdyksen eli niin sanotun banner-viestin. Tyypillisesti tekstissä kerrotaan ohjelmiston copyright-teksti, versionumero ja muuta teknistä tietoa. Niiden jälkeen tulee mahdollinen kirjautumisikkuna, jossa kysytään käyttäjätunnus ja salasana.

Shodan tallentaa banner-viestit tietokantaansa, josta niitä voi hakea erilaisilla suodattimilla ja lisäehdoilla. Tahattomasti netissä näkyvien palveluiden löytämiseksi Shodan kokeilee myös epästandardeja porttiosoitteita. Jotta kyselyt ja porttiskannaukset eivät turhaan laukaisisi kohteessa hälytyksiä, kokeilut tapahtuvat satunnaisessa järjestyksessä satunnaisiin aikoihin.

Maarajoitusten kiertämiseksi Shodanin verkkoa kartoittavat palvelimet on hajautettu eri puolille maailmaa. Yhdysvaltojen lisäksi niitä on muun muassa Ranskassa, Romaniassa, Vietnamissa, Kiinassa ja Islannissa.

Shodan hakee vain julkisessa netissä näkyviä kohteita. Sen vaarallisuus on seurausta helposta käyttöliittymästä ja palveluiden huonosta ylläpidosta. Hakukoneen avulla aloittelevakin hakkeri löytää haavoittuvia kohteita, joihin iskeä.

Ylläpidon osaamattomuudesta johtuen netissä on valtavasti laitteita, joiden hallintaliittymään pääsee kuka tahansa, joka sattuu löytämään oikean ip-osoitteen ja porttinumeron. Pahimmassa tapauksessa käyttäjätunnus ja salasana ovat luokkaa ”admin” ja ”1234” tai yleisesti tunnettuja valmistajakohtaisia oletusarvoja.

Shodanilla löytyneistä kohteista on uutisoitu medioissa. Tällaisia ovat esimerkiksi sairaalan sydänmonitori, hotellin viinikaappi, kolmen megawatin vesivoimalaitos, uima-altaan klooripumppu, peltipoliiseja, liikennevalojen ohjausjärjestelmiä, ranskalainen köysirata, autopesulaite, krematorio, huvipuisto ja tanskalainen jääkiekkokaukalo.

Säätöjä muuttamalla hakkeri voisi aiheuttaa suurta vahinkoa ja jopa ihmishenkien menetystä. Aina ei tiedetä, missä kaupungissa tai edes missä maassa löydetyt laitteet sijaitsevat, joten niiden omistajia on vaikea varoittaa.

Myös suomalaiset tietoturvatutkijat ovat hyödyntäneet Shodania.  Uusissa tutkimuksissa trendi on ollut laskeva.

Shodan ei ole hyväntekeväisyyttä vaan selkeää bisnestä. Perusversio on ilmainen, mutta vähänkin aktiivisempi käyttö edellyttää rekisteröintiä. Jopa käyttöohje on myynnissä: pdf-tiedosto maksaa viisi dollaria.

Sitten on vielä kuukausimaksu. Freelancer-tasolla (59 dollaria) saa enintään miljoona tulosta ja pääsyn hakusuodattimiin. Small Business -lisenssi on 299 dollaria ja täysi yrityslisenssi 899 dollaria kuukaudessa.

Hakukone tutkii palvelinten alttiuden erilaisille haavoittuvuuksille kuten Heartbleed-aukolle. Näiden tietojen näkeminen vaatii vähintään Small Business -tasoa.

Tuloksia voi tarkastella sivulla selaten tai niistä voi koota raportteja, joista kuitenkin veloitetaan krediittejä. Yksi krediitti maksaa viisi dollaria. Suuremmissa määrissä on volyymialennusta.

Web-käyttöliittymän lisäksi Shodania voi käyttää komentorivipohjaisena, mikä mahdollistaa hakukomentojen skriptaamisen ja tulosten ohjaamisen muihin työkaluihin.

Käyttö onnistuu myös apin eli rajapinnan kautta. Esimerkiksi SearchDiggity tarjoaa 167 valmista kyselyä, jotka auttavat löytämään huonosti suojattuja kohteita.

Vielä yksi käyttömuoto on Chrome-laajennus, joka näyttää web-palvelimen käyttämät portit ja ohjaa hakukoneen sivulle tarkempien tulosten katsomiseksi.

Tietoturva-ammattilainen löytää Shodanille runsaasti käyttökohteita. Sillä voi esimerkiksi tarkistaa oman ja auditoitavien verkkojen ulospäin näkyvät palvelut.

Shodanilla voi laskea kiinnostavia tilastoja ja tehdä jopa markkinatutkimusta. Shodan kertoo, mikä on eniten käytetty Apache-ohjelman versio ja montako julkista ftp-palvelinta maailmasta tai tietystä maasta löytyy.

## Verkkoon avoinna olevan Mysql-serverit pääkaupunkiseudulla
![](https://gitlab.dclabra.fi/wiki/uploads/upload_df0faa49e091ee213867d64c4530d010.png)

## Apache palvelimet Kajaanissa

![](https://gitlab.dclabra.fi/wiki/uploads/upload_926ed4d90ce5704e216eaffe886d0b17.png)

Shodanilla on löytynyt verkosta muun muassa suojaton sydänmonitori, köysirata, vesivoimala ja krematorio.

Shodanilla löytyy pikaisellakin haulla Suomesta kohteita, joiden tietoturva herättää epäilyksiä. Vantaalta Shodan löysi Foxin ics-laitteen, jonka station.name-kenttä sisälsi liikekiinteistön osoitteen.

Erään puhelinyhtiön omistamasta verkosta löytyi avoin telnet-yhteys Ciscon CP-konfigurointiohjelmaan. Yksi Windows-kone oli kytketty nettiin kaikki portit avoinna, jopa työaseman netbios-nimi oli näkyvissä ja VNC-etäkäyttöyhteys odottamassa.






