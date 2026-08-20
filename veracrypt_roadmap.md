# VeraCrypt Android – turvallisuus- ja toteutustiekartta

## Toteutustilanne 2026-08-20

- Vaiheet 1–4: toteutettu ja paikalliset debug/release-buildit läpäisty.
- Vaiheet 5–7: koodi ja deterministiset FAT32/exFAT/SAF-regressiotestit
  toteutettu; FAT32-fixture sisältää 192 KiB:n moniklusteritiedoston ja exFAT-
  fixture fragmentoidun FAT-ketjun. BPB-, FAT- ja directory-fuzzerit läpäisivät
  paikallisesti 50 000 syötettä kukin ASan/UBSanilla, ja ne ajetaan CI:ssä joka
  yö. Instrumentointitestit (mukaan lukien SAF cancellation, unmount, ulkoinen
  client ja Activity-recreate) kääntyvät molemmille ABI:ille. Varsinainen ajo on
  CI:n KVM-emulaattorissa pakollinen, koska paikallisessa ympäristössä ei ole
  KVM:ää. Oikealla VeraCryptillä luodun FAT32/exFAT-corpuksen tulokset ovat yhä
  julkaisuportti; nykyiset filesystem-fixturet ovat riippumattoman generaattorin
  tekemiä VeraCrypt-formaattisia testivolyymeja.
- Vaihe 8: manifestin kovennus, release-smoke, SHA-pinnattu CI, secret- ja
  dependency/license-scan, SBOM, öinen ASan/UBSan/fuzz-ajo ja uhkamalli on
  toteutettu. Auditointiaineisto on koottu tiedostoon
  `docs/INDEPENDENT_AUDIT_HANDOFF.md`. Riippumaton kryptografia-/native-auditointi ja sen P0/P1-löydösten
  sulkeminen vaatii ulkopuolisen auditoijan eikä sitä voi kuitata koodimuutoksella.
- Vaiheet 9–11: eivät ole aktivoitavissa ennen vaiheen 8 auditointiporttia.
  Turvallinen suunnittelurajaus on dokumentoitu tiedostossa
  `docs/FUTURE_MUTATION_DESIGN.md`; write/create/NTFS/FUSE pysyvät poissa API:sta.

## 1. Yhteenveto ja julkaisupäätös

Lukujen 1–5 löydöslista on alkuperäinen auditointisnapshot ennen yllä kuvattuja
toteutuksia. Tämänhetkinen porttitilanne on tämän tiedoston alun
`Toteutustilanne`-osiossa; historiallisia löydöksiä ei saa tulkita väitteeksi,
että jo korjattu write-/global-session-koodi olisi edelleen käytössä.

Projektissa on hyvä monimoduulinen lähtörakenne ja aidosti hyödyllinen read-only-polku, mutta sitä ei tule vielä julkaista VeraCrypt-yhteensopivana tai tietoja muuttavana sovelluksena. Turvallisin seuraava julkaisutavoite on **rajattu, read-only AES + PBKDF2-HMAC-SHA-512 + FAT32/exFAT -milestone**, jossa tuetut formaatit todistetaan yhteensopivuustesteillä. NTFS, säiliön luonti, kirjoitus ja root/FUSE pidetään pois käytöstä, kunnes niiden hyväksymiskriteerit täyttyvät.

Tarkastus kattoi Gradle- ja CI-määritykset, Android-manifestit, Kotlin/SAF-koodin, JNI/C++-ytimen sekä testit. Tämä dokumentti kuvaa todellisen tilan tarkastushetkellä; käyttöliittymässä create-, import- ja root/FUSE-painikkeita on jo piilotettu, mutta taustalla on edelleen keskeneräisiä native-rajapintoja.

### Riskiluokitus

| Luokka | Merkitys | Keskeiset löydökset |
|---|---|---|
| P0 | Estää tuotantokäytön tai voi vaarantaa salauksen/tiedot | yksi globaali native-sessio, rajoittamaton formaattiväite, keskeneräinen kirjoitus, luontirutiinin jäänyt kuollut koodi |
| P1 | Korjataan ennen ominaisuuden aktivointia | oma krypto ilman kattavaa vektorikattausta, exFAT-metadatan puutteet, SAF:n prosessi- ja elinkaariongelmat |
| P2 | Laatu, ylläpidettävyys tai suorituskyky | 3 000-rivinen JNI-tiedosto, vanhentunut dokumentaatio/CMake-kommentti, niukka testikattavuus |

## 2. Nykytilan arviointi

### Hyvin tehty

- Moduulijako (`app`, `core-api`, `core-native`, `provider-saf`) on järkevä lähtökohta ja AndroidX/SAF-perusta on nykyaikainen (minSdk 26, target/compileSdk 35, Java 17).
- Header-polussa on jo olennaisia suojauksia: `fstat`, täydet `pread64`/`pwrite64`-silmukat, `EINTR`-käsittely, offset-overflow-tarkistuksia ja sektoreiden file/encrypted-area-rajojen tarkistus.
- Headerista tarkistetaan VERA-magic, CRC:t, sektorikoko ja osa geometriasta. Salasanan Kotlin-`ByteArray` nollataan avauksen ja luontiyrityksen jälkeen; native-puolella johdettu avain ja purettu header nollataan onnistumis- ja useissa virhepoluissa.
- FAT32- ja exFAT-lukijat tarkistavat useita BPB-arvoja, rajoittavat cluster-ketjun kierroksia cluster-määrällä ja hyväksyvät vain kanonisen absoluuttisen polun.
- Read-only SAF-provider estää kirjoitustilat ja streamaa pipeen pienissä paloissa. UI myös piilottaa nykyisin keskeneräiset container-create-, import- ja root/FUSE-toiminnot.
- Root/FUSE-placeholder ei enää suorita root-shelliä. Tämä on merkittävä parannus aiempaan command-injection-riskiseen malliin.
- CI rakentaa debug APK:n ja ajaa ainakin yhden instrumentoidun header-avaustestin; testifixturelle tehdään SHA-256-tarkistus.

### Tekninen velka ja ristiriidat

- `veracrypt_jni.cpp` sisältää krypton, headerin, sektor-I/O:n, FAT32:n, exFAT:n, kirjoituksen, luontikoodin ja JNI:n samassa tiedostossa. Tämä vaikeuttaa auditointia, fuzzingia ja korjausten turvallista eristämistä.
- API on prosessilaajuisen `g_session`-olion ja raaka-`fd`:n varassa. Mutex serialisoi kutsut, mutta uusi avaus mitätöi kaikkien muiden avauksen; session elinkaari ei ole eksplisiittinen eikä native `closeSession` -kutsua ole.
- `VeraCryptDocumentsProvider` käyttää staattista prosessimuistia ja omistaa Activityltä saadun PFD:n. Provider voi Androidissa syntyä eri prosessiin tai uudelleenkäynnistyä ilman Activityn muistia; tällainen mount-malli ei ole pysyvä eikä luotettava SAF-sopimus.
- UI, README ja native-koodi eivät kuvaa samaa ominaisuusjoukkoa. README väittää luomisen, write-pipelinen ja FUSE-valmiuden, vaikka luonti ja FUSE palauttavat `-4` ja UI on read-only.
- `CMakeLists.txt` puhuu yhä “stubista”, vaikka se rakentaa suuren toteutuksen. `ContainerReader`-rajapinnalle ei ole toteutusta.
- Unit-testit testaavat pääosin dataluokkia ja `2 + 2`; native-instrumentointi testaa yhden keinotekoisen, vain 512 tavun header-fixturen. Se ei testaa oikeaa VeraCryptin luomaa tiedostojärjestelmäsäiliötä, sektoreita, listauksia, virheitä tai kilpailutilanteita.

## 3. Tietoturva- ja suorituskykypuutteet

### 3.1 Salaus, header ja salaisuudet

1. **Kryptografinen yhteensopivuus on liian kapea ja hardcodattu.** `nativeParseHeader` kokeilee vain AES-XTS:ää ja PBKDF2-HMAC-SHA-512:ää 500 000 kierroksella. Se ei tee VeraCryptin tukemaa PRF-/iteraatio-/PIM-kokeilua eikä tuota täsmällistä `Unsupported algorithm` -virhettä. Älä väitä yleistä VeraCrypt-tukea ennen testattua algoritmimatriisia.
2. **Oma SHA-512/HMAC/PBKDF2/AES/XTS-toteutus on korkean riskin auditointikohde.** Sitä ei ole erotettu, eikä sille ole NIST-, RFC- tai VeraCrypt-vektoreita. Käytä ensisijaisesti auditoitua, version lukittua natiivia kryptokirjastoa/adapteria; jos toteutus säilytetään, testaa se riippumattomilla vektoreilla ja ulkopuolisella auditoinnilla.
3. **Salasanan ja välitilojen nollaus ei ole kokonaisvaltainen.** HMAC:n pinopuskurit (`k0`, `ipad`, `opad`, `inner`, `U`, `T`), AES key schedule -välitilat ja useat `std::vector`-puskurit jäävät nollaamatta. Java/Kotlin-merkkijono syntyy lisäksi `EditText.text.toString()`-kutsussa eikä sitä voi luotettavasti pyyhkiä. Käytä mahdollisuuksien mukaan `CharArray`/`ByteArray`-polkua, minimoi kopiot ja tee `secure_zero` kaikille native-salaisuuksille RAII-guardilla.
4. **CRC ei ole autentikointi.** VeraCryptin XTS + header-CRC ei tarjoa tiedostodatalle MAC:ia tai tamper detectionia. Tämä on formaatin ominaisuus, joka on dokumentoitava selkeästi; yhteensopivuusformaattiin ei saa lisätä omaa MAC:ia huomaamatta.
5. **Header-geometria on osin validoitu, mutta ei täysin sidottu.** Vahvista `encryptedAreaSize > 0`, sektorikerrannaisuus, `dataOffset + encryptedAreaSize <= fileSize`, volume size -suhteet, backup-headerin/hidden-volume-tapausten eksplisiittinen hylkäys sekä kaikki tuetut header-versiot. Palauta eri virhekoodit väärälle salasanalle, vaurioituneelle headerille ja tuetulle mutta toteuttamattomalle algoritmille.
6. **Lokit sisältävät arkaluonteista metadataa.** Native lokittaa polkuja, fd:n, kokoja ja filesystemin; provider lokittaa fd:n. Release-buildissa käytä minimilokia, älä koskaan lokita salasanaa, avaimia, yksityisiä polkuja tai säiliöiden tunnistettavia metatietoja.

### 3.2 FAT32 ja exFAT

1. **FAT32-tuki ei ole täydellinen.** Pitkän nimen ketjujen järjestys/checksum ja UTF-16-surrogaatit vaativat tiukkaa validointia. Cluster-to-sector-lasku palauttaa `uint32_t`:n ja tarvitsee overflow- sekä cluster-aluevarmistukset jokaiselle käytölle. FAT-ketjun yksittäisiä vierailuja ei merkitä nähdyiksi; nykyinen askelraja estää ikuisen silmukan, muttei anna täsmällistä virhettä tai estä toistuvaa I/O:ta.
2. **exFAT-tuki on vielä kevyempi.** BPB:stä ei validoida boot-regionin checksumia, volume flagsia, FAT/bitmap/upcase-tauluja eikä allocation bitmapia. Varaus skannaa FAT:ia eikä päivitä allocation bitmapia tai free-space-metadataa, joten se voi korruptoida standardin exFAT-volyymin. Directory-entry setin checksumia, secondary-countia, name lengthiä, stream flagsia ja `NoFatChain`-semantiikkaa ei validoida/toteuteta kattavasti.
3. **exFAT:n tiedostokoko typistyy 32 bittiin `DirEntry.sizeBytes`-kentässä.** Yli 4 GiB tiedostot listautuvat väärin ja voivat aiheuttaa väärän streamauksen tai write-päätöksen. Tee koosta `uint64_t` myös native-mallissa ja JNI/Kotlin-ketjussa.
4. **NTFS tunnistetaan mutta sitä ei tueta.** Tunnistuksen tarjoaminen ei ole tuki: listaus palauttaa virheen, kirjoitus on disabloitu eikä luontiin ole formatteria. Poista NTFS käyttöliittymästä ja julkisista kyvykkyysväitteistä, kunnes käytössä on kypsä read-only-kirjasto ja erillinen turvallisuusarvio. NTFS-kirjoitusta ei pidä toteuttaa kevyenä parserilaajennuksena journalin, attribute-listojen, $Bitmapin ja recovery-semanttiikan vuoksi.
5. **Kirjoituspolku on datakorruptioriski.** FAT32/exFAT-varaus muuttaa metatietoja ennen kuin koko operaatio on onnistunut; rollbackia, journalia, `fsync`/durability-sopimusta, truncate/deleteä, collision-politiikkaa ja interruption recoverya ei ole. Vaikka UI piilottaa importin, JNI-rajapinta on edelleen käytettävissä.

### 3.3 Säiliön luonti

1. `nativeCreateContainer` palauttaa nyt aina `-4`, mikä on oikein väliaikainen suoja. Sen `#if 0` -koodi on kuitenkin poistettava tai siirrettävä dokumentoiduksi suunnitelmaksi: se kirjoittaa vain boot-sektorin tunnisteen (FAT32/exFAT/NTFS), ei tiedostojärjestelmää.
2. Kuollut luontikoodi ei alustaisi FAT32:n BPB:tä, FSInfoa, FAT-kopioita, root-hakemistoa tai backup-boot-sektoria; exFAT:n boot regionia, checksum-sektoreita, allocation bitmapia, upcase-taulua ja root entry -rakennetta; eikä NTFS:n välttämättömiä metadata-tiedostoja. Tällainen image ei ole käyttökelpoinen volume.
3. Luonnissa on myös tarpeettomia `lseek`/`write`-kutsuja, osittaisen kirjoituksen riski, virhepolkujen puutteellinen nollaus ja ei-atominen failure handling. Älä ota sitä käyttöön korjaamalla yksittäisiä kenttiä.
4. Toteutuksen on luotava koko image väliaikaiseen, sovelluksen hallitsemaan tiedostoon, `fsync`attava, validoitava sulje–avaa–listaa–kirjoita–avaa uudelleen -ketjulla ja vasta sitten julkaistava kohde URI:in turvallisella replace/commit-mallilla. SAF-providerien atomisuusrajoitteet on dokumentoitava.

### 3.4 Android, SAF ja suorituskyky

1. Activity avaa säiliön ensin `rw`-tilassa vaikka käyttöliittymä on read-only. Avaa read-only-milestonessa aina `r`; pyydä `rw` vasta kirjoitusmilestonessa ja näytä erillinen vahvistus.
2. PFD:n sulkeminen unmountissa voi kilpailla aktiivisen provider-/viewer-streamin kanssa. Raaka fd voidaan myös uudelleenkäyttää OS:ssa. Korvaa fd-parametri opaque session handella ja hallitulla `dup`-omistajuudella.
3. SAF-providerin staattinen cache ja mount eivät säily prosessikuoleman yli. Providerin on joko oltava vain sovelluksen sisäinen eksplisiittinen preview-palvelu tai sen on käytettävä pysyvää, käyttäjän hyväksymää URI-grantia ja session-palvelua, joka palauttaa selkeän “mount expired” -virheen uudelleenkäynnistyksessä.
4. `queryDocument` palauttaa tyhjän cursorin tuntemattomasta ID:stä virheen sijaan, ja `ContainerViewerProvider.query()` voi antaa metadataa olemattomalle polulle. Validoi dokumentti aina sessionista ja palauta `FileNotFoundException`/selkeä provider-virhe.
5. Preview antaa URI:n ulkoiselle katselijalle. Pipe rajoittaa altistuksen streamiin, mutta ulkoinen sovellus saa plaintextin; käyttäjälle on kerrottava tästä, grant on rajattava ja streamit peruttava unmountissa. Älä käytä `ACTION_VIEW`-polkua salaisille tiedoille ilman näkyvää varoitusta.
6. Koko filesystem- ja kryptotyö serialisoituu yhdellä mutexilla. Se on turvallisempi kuin data race, mutta pitkä PBKDF2, suuri luku tai provider-stream estää kaiken muun. Container-kohtainen serial executor/lock ja cancellable I/O parantavat vasteaikaa ilman avainten sekoittumista.

## 4. Tarkat korjaukset ja refaktorointi

### API ja sessionhallinta

- Korvaa `nativeParseHeader(fd, password): Int` mallilla `nativeOpen(fd, password): Long` ja `nativeClose(session: Long)`. Käytä satunnaistettua/ei-uudelleenkäytettävää opaque handlea, session-taulua ja RAII-pohjaista zeroizationia.
- Muuta kaikki native-kutsut muotoon `nativeListDir(session, path)`, `nativeReadFile(session, path, offset, length)` jne. Native dupaa fd:n tai ottaa sen yksiselitteisesti omistukseensa; älä tarkista sessiota pelkällä fd-numerolla.
- Lisää `ContainerSession`/`ContainerRepository` Kotlin-puolelle: yksi omistaja, `Mutex` tai yksisäikeinen dispatcher per sessio, sulku odottaa aktiiviset operaatiot, ja `Closeable`/lifecycle on idempotentti.
- Laajenna `OpenResult`: `WrongPassword`, `UnsupportedAlgorithm`, `CorruptHeader`, `UnsupportedFileSystem`, `IoError`, `Cancelled`. Älä niputa niitä yhdeksi `-1`/`-2`-paluuarvoksi.
- Poista tai pidä sisäisenä kaikki write-, allocate- ja timestamp-JNI-metodit, kunnes write-milestone valmistuu.

### Native-ytimen jako

- Pilko `veracrypt_jni.cpp`: `jni_bridge.cpp`, `session.{h,cpp}`, `secure_memory.{h,cpp}`, `header.{h,cpp}`, `sector_io.{h,cpp}`, `crypto_adapter.{h,cpp}`, `fat32_reader.{h,cpp}`, `exfat_reader.{h,cpp}` ja vain myöhemmin erilliset writerit.
- Lisää `-Wall -Wextra -Werror` (korjaa löydökset), `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2` soveltuvin osin, näkyvyyden rajaus ja debug-profiiliin ASan/UBSan. Älä aja ASania production APK:ssa.
- Toteuta yhteiset checked-aritmetiikka-apurit (`checked_add`, `checked_mul`, sector/cluster-range) ja käytä niitä jokaisessa parserissa.
- Käytä Unicode-kirjastoa tai tiukkaa UTF-16/UTF-8-validaattoria; hylkää invalidit surrogate-parit ja epäkelvot directory entry setit.

### Filesystemit ja ominaisuusrajaus

- Milestone B: FAT32 + exFAT **vain read-only**, nested-directoryt, 64-bittiset koot, kokonaiset path resolution -testit, syklien havaitseminen `visited`-joukolla sekä input/output- ja directory-entry-rajoitukset.
- FAT32: validoi media/BPB-signaturet, total sectors, FAT-kapasiteetti suhteessa cluster-määrään, FSInfo/backup-sektorit tarpeen mukaan ja LFN:n järjestys, checksum sekä UTF-16.
- exFAT: validoi boot region/checksum, pää- ja backup-boot-region, volume length, FAT, cluster heap, allocation bitmap, upcase-table ja entry-set checksum. Tue `NoFatChain` vain oikein tai hylkää se eksplisiittisesti.
- NTFS: pidä `Unsupported`-tilassa. Älä lisää NTFS-luontia tai kirjoitusta; mahdollinen read-only-tuki suunnitellaan erillisenä integraationa ja lisenssi-/turvallisuusarvioituna riippuvuutena.

### UI, provider ja dokumentaatio

- Piilota tai poista kuollut create/root/import-koodi ja resurssit, tai suojaa ne feature flagilla, jonka oletus on pois. Älä jätä saavutettavia native-metodeja ilman kyvykkyystarkistusta.
- Toteuta nested-directoryn navigointi vasta native path resolution -testien jälkeen; nykyinen UI sanoo sen olevan tukematon vaikka osa native-polusta käsittelee hakemistoja.
- Muuta provider `SessionRepository`-pohjaiseksi, lisää per-operaation cancellation, fd/session snapshot, streamien rekisteri ja unmountin hallittu peruutus. Älä kirjaa fd:tä.
- Korjaa document-ID:n normalisointi ja varmista, että provider ei koskaan palauta metadataa tai dataa tuntemattomasta, hakemistoksi naamioidusta tai session ulkopuolisesta polusta.
- Päivitä README, strings ja CMake vastaamaan testattua tilaa. Lisää selkeä uhkamalli: plaintext-näyttö, XTS:n autentikoimattomuus, rooted-device-rajat ja tuetut algoritmit.

## 5. Gradle, allekirjoitus ja CI/CD

### Pakollinen release-allekirjoitusmalli

`app/build.gradle.kts` ei saa lukea `local.properties`-, `signing.properties`- tai muuta tiedostopohjaista salaisuuslähdettä. Poista nykyinen `Properties`-import, `signing.properties`-fallback sekä vanhat `KEYSTORE_*`-nimet. Käytä vain Bash/CI:n ympäristömuuttujia ja tarkista niiden olemassaolo ennen asetusten käyttöä:

```kotlin
signingConfigs {
    create("release") {
        val keystorePath = System.getenv("VERACRYPT_KEYSTORE_PATH")
        val keystorePassword = System.getenv("VERACRYPT_KEYSTORE_PASSWORD")
        val keyAliasValue = System.getenv("VERACRYPT_KEY_ALIAS")
        val keyPassword = System.getenv("VERACRYPT_KEY_PASSWORD")

        if (keystorePath != null &&
            keystorePassword != null &&
            keyAliasValue != null &&
            keyPassword != null
        ) {
            storeFile = file(keystorePath)
            storePassword = keystorePassword
            keyAlias = keyAliasValue
            keyPassword = keyPassword
        }
    }
}
```

Lisäksi release-buildin on epäonnistuttava selkeällä Gradle-virheellä, jos jokin muuttuja puuttuu; debug-buildin on silti toimittava ilman niitä. Tee validointi vain silloin, kun Gradle-task graph sisältää release-signing/assemble/bundle -tehtävän. `buildTypes.release.signingConfig` asetetaan vain, kun kaikki neljä arvoa ovat ei-tyhjiä; muutoin heitetään `GradleException` release-taskille. Tarkista myös, että keystore-polku osoittaa luettavaan tiedostoon ilman että salasanoja tulostetaan.

CI:n release-jobissa keystore dekoodataan `$RUNNER_TEMP/release.keystore`-tiedostoon ja sille asetetaan täsmälleen:

```yaml
VERACRYPT_KEYSTORE_PATH: ${{ runner.temp }}/release.keystore
VERACRYPT_KEYSTORE_PASSWORD: ${{ secrets.VERACRYPT_KEYSTORE_PASSWORD }}
VERACRYPT_KEY_ALIAS: ${{ secrets.VERACRYPT_KEY_ALIAS }}
VERACRYPT_KEY_PASSWORD: ${{ secrets.VERACRYPT_KEY_PASSWORD }}
```

Keystore-base64 voi säilyä nimellä `VERACRYPT_KEYSTORE_BASE64`, mutta vanhat `KEYSTORE_PATH`, `KEYSTORE_PASSWORD`, `KEY_ALIAS` ja `KEY_PASSWORD` poistetaan workflowsta, README:stä ja scriptiesimerkeistä. Keystore poistuu runnerin tilapäishakemiston mukana; älä kirjoita avaimia repo- tai Gradle-property-tiedostoihin.

### Muut build- ja toimitusketjukorjaukset

- Pinnaa **kaikki** GitHub Actions -viittaukset täysiin commit-SHA:ihin (`checkout`, `setup-java`, `upload-artifact`, emulator runner sekä setup-android). Nykyisin vain yksi on pinnautunut.
- Poista HEAD-URL:sta ladattava testifixture. Koska fixture on repossa, käytä sitä; jos lataus on välttämätön, käytä immutable commit-URL:ia ja SHA-256:ta.
- Lisää `:core-native:connectedAndroidTest` pakolliseksi branch protectionissa, sekä native unit-testit hostille jos CMake-testiharness luodaan.
- Lisää dependency- ja secret-scanning, SBOM, license scanning sekä viikoittainen fuzz/sanitizer-ajastus.
- Ota R8/minify käyttöön vasta providerin, JNI:n ja release-smoke-testin jälkeen. Nykyinen `isMinifyEnabled = false` on hyväksyttävä väliaikaisesti, mutta se on kirjattava päätökseksi.

## 6. Askeleittainen toteutussuunnitelma (Action Plan)

Jokainen vaihe on tehtävä järjestyksessä. Agentti ei siirry seuraavaan vaiheeseen, elleivät vaiheen hyväksymiskriteerit ja testit läpäise. Ominaisuuden epäonnistuessa turvallinen tila on `Unsupported`/read-only, ei osittainen toiminto.

1. **Lukitse lähtötilanne ja kyvykkyysrajaus.**
   - Tee `SUPPORTED_FEATURES.md` ja päivitä README: tuettu vain AES/PBKDF2-SHA-512/FAT32/exFAT read-only, jos tämä todistetaan; NTFS, create, write ja FUSE ovat unsupported.
   - Poista julkiset väitteet write/create/FUSE-valmiudesta ja kuollut `#if 0` create-koodi tai siirrä se versionhallintahistoriaan.
   - Avaa säiliö `r`-tilassa. Pidä create/import/root UI ja write-JNI pois käytöstä.
   - Hyväksyminen: UI, README, native return codes ja SAF flags ovat keskenään yhtäpitävät.

2. **Korjaa allekirjoitus- ja CI-salaisuudet.**
   - Päivitä `app/build.gradle.kts` edellä määritettyyn neljään `VERACRYPT_*`-ympäristömuuttujaan, vain `System.getenv()`-lukuun ja release-taskin fail-fast-validointiin.
   - Poista `Properties`/`signing.properties`-fallback kokonaan; älä käytä `local.properties`-tiedostoa.
   - Päivitä CI-secrets, README ja release-smoke-test. Pinnaa Actions SHA:ihin ja poista mutable HEAD fixture -lataus.
   - Hyväksyminen: `assembleDebug` toimii ilman ympäristömuuttujia; `assembleRelease` epäonnistuu selkeästi, kun yksikin neljästä puuttuu; signed release onnistuu vain, kun kaikki neljä ovat asetettu.

3. **Määrittele ja toteuta session elinkaari.**
   - Suunnittele opaque native session handle, fd:n `dup`-omistajuus, session state machine ja `close`-semantiikka.
   - Toteuta Kotlin `ContainerSessionManager` per-session dispatcherilla ja korvaa providerin staattinen fd/cache sillä.
   - Lisää close-, unmount-, prosessikuolema- ja kahden samanaikaisen containerin testit.
   - Hyväksyminen: toinen avaus ei korvaa ensimmäisen avaimia; unmount kesken streamin peruu streamin hallitusti eikä käytä suljettua tai uudelleenkäytettyä fd:tä.

4. **Eristä ja varmista crypto/header.**
   - Pilko native-koodi; lisää `SecureBuffer`/RAII-zeroization, yhdenmukaiset virheet ja checked-aritmetiikka.
   - Lisää SHA-512, HMAC, PBKDF2, AES-256 ja XTS -vektorit sekä header round-trip/negative-testit. Käytä useita oikealla VeraCryptillä tehtyjä fixtureita (vain avoimesti testikäyttöön luotuja salasanoja).
   - Dokumentoi tuettu PRF/PIM/cipher-matriisi; hylkää muu täsmällisesti. Validoi koko header-geometria ja jatkuvat volume-rajat.
   - Hyväksyminen: väärä salasana, korruptoitu header, tuettu mutta toteuttamaton algoritmi ja I/O-virhe ovat eroteltuja; kaikki vektorit läpäisevät molemmilla ABI:lla.

5. **Tee read-only FAT32 robustiksi.**
   - Toteuta täydellinen BPB/FAT/cluster/LFN-validointi, 64-bittiset offsetit ja koot, visited-set-syklitarkistus sekä maksimirajat entryille/nimille/listauksille.
   - Toteuta ja testaa nested directory traversal sekä tiedoston luku yli sector- ja cluster-rajojen.
   - Lisää fuzz-targetit BPB:lle, FAT:lle ja directory entryille; aja ASan/UBSan nightlyssä.
   - Hyväksyminen: vahingoittunut fixture ei kaada tai jumita prosessia; oikean VeraCrypt FAT32-volumeen luodut nested file -testit toimivat.

6. **Tee read-only exFAT robustiksi.**
   - Toteuta boot-region/checksum-, allocation-bitmap-, upcase- ja entry-set-validation, `NoFatChain`-käsittely tai eksplisiittinen hylkäys sekä 64-bittiset file sizes.
   - Lisää nested path resolution ja suuret/fragmentoituneet tiedostot.
   - Hyväksyminen: oikealla VeraCrypt exFAT-volumella root/nested/list/read toimii, yli 4 GiB metadata säilyy oikein ja virheellinen exFAT hylätään turvallisesti.

7. **Viimeistele Android/SAF read-only-polku.**
   - Toteuta providerin dokumenttien auktoritatiivinen lookup sessionista, cancellation, stream registry, MIME-käsittely ja selkeät virheet.
   - Tee UI:n nested navigation vastaavaan native-tukeen, käsittele rotation/background/restore ja näytä plaintext-jaon varoitus ennen ulkoista previewta.
   - Lisää instrumentoidut DocumentsUI-/ulkoinen-client-testit ja provider-prosessin uudelleenkäynnistystesti.
   - Hyväksyminen: ei tuntemattoman ID:n metadataa, ei directory-as-file-avauksia, eikä provider kaadu/anna dataa unmountin jälkeen.

8. **Julkaise ja auditoi read-only milestone.**
   - Ota käyttöön release-smoke test, dependency/secret scan ja SBOM; käy läpi manifest, backup, URI-grant ja release-logit.
   - Tee uhkamallikatselmus ja ulkopuolinen kryptografia-/native-auditointi ennen tuotantojulkaisua.
   - Hyväksyminen: kaikki P0/P1 read-only-havainnot suljettu, CI pakollinen, allekirjoitettu release reproduktoitavissa salaisuuksia paljastamatta.

9. **Suunnittele säiliön luonti erillisenä projektina.**
   - Valitse formatter-strategia: auditoitu lisensoitu kirjasto tai tarkasti rajattu oma FAT32/exFAT formatter. NTFS ei kuulu tähän vaiheeseen.
   - Luo ensin temp-image, käytä CSPRNG:tä ilman fallbackia, kirjoita oikea VeraCrypt-header ja oikea FS, `fsync`aa, sulje, avaa, listaa, kirjoita testitiedosto ja avaa uudelleen. Julkaise kohde vasta validoinnin jälkeen.
   - Lisää failure-injection ja cleanup-strategia SAF-kohteille.
   - Hyväksyminen: sovelluksen luoma FAT32- ja exFAT-säiliö avautuu sekä sovelluksella että standardilla VeraCryptillä, ja tiedostot säilyvät uudelleenavauksessa.

10. **Toteuta kirjoitus vasta hyväksytyn suunnitelman jälkeen.**
    - Määrittele API-semanttiikka (`create`, overwrite, append, truncate, delete, rename), atomicity ja crash recovery.
    - FAT32:ssa päivitä kaikki FAT-kopiot ja directory metadata johdonmukaisesti. exFAT:ssa päivitä allocation bitmap, FAT/NoFatChain, stream extension, checksums ja free-space metadata oikein.
    - Tee transaction/rollback tai turvallinen write-ahead/recovery-malli; lisää full disk-, interruption-, power-loss-simulaatio- ja interoperabiliteettitestit.
    - Hyväksyminen: ei metadata- tai data-korruptiota keskeytyksessä; kaikki SAF-flags vastaavat toteutusta.

11. **Käsittele NTFS ja root/FUSE viimeisinä, erillisinä rajattuina päätöksinä.**
    - NTFS: aloita vain auditointikelpoisella read-only-ratkaisulla ja lisenssiselvityksellä. Kirjoitusta ei toteuteta ilman täyttä journaling/recovery-suunnitelmaa.
    - FUSE: toteuta oikea daemon/session-protokolla, allowlistattu mount point, argumenttivälitys ilman shell-interpolointia, unmount/crash cleanup ja plaintext-permission-politiikka. Älä bind-mounttaa salattua tiedostoa.
    - Hyväksyminen: mountattu näkymä on aidosti purettu filesystem, ei shell-injektiota, eikä plaintext jää saataville unmountin tai crashin jälkeen.

## 7. Testausmatriisi ja valmistumiskriteerit

- **Crypto/header:** viralliset hash/HMAC/PBKDF2/AES/XTS-vektorit, oikeat VeraCrypt-fixturet, wrong-password, korruptio, PIM/PRF/algoritmi-unsupported.
- **FAT32/exFAT:** root ja nested, LFN/Unicode, empty/large/fragmented file, yli 4 GiB metadata, loop, invalid BPB, invalid directory set, truncated image ja fuzzing.
- **Android/SAF:** avaus/sulku/rinnakkaisuus, rotation, process death, URI permission, external DocumentsUI, cancellation, unmount kesken lukemisen sekä plaintext preview -grant.
- **Write/create (vain myöhemmin):** close/reopen, VeraCrypt-interoperabiliteetti, full disk, keskeytys jokaisessa metadata-vaiheessa, crash recovery ja duplicate name/truncate/delete.
- **Native-laatu:** ASan/UBSan nightly, static analysis, `-Werror`, regression corpus, reproducible fixture provenance.

Tuotantovalmis read-only-julkaisu edellyttää, että kaikki yllä olevan vaiheen 8 hyväksymiskriteerit täyttyvät, tuetut muodot on todistettu oikeilla VeraCrypt-volyymeilla, session avaimia ei sekoiteta rinnakkaisessa käytössä, salaisuudet nollataan määritellyissä elinkaaripoluissa ja README/UI/SAF-kyvykkyydet vastaavat täsmälleen toteutusta.
