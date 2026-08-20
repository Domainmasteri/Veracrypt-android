# VeraCrypt Android – tarkka jatkotilanne

Päivitetty: 2026-08-20 (UTC)

## 1. Tavoite ja työjärjestys

Voimassa oleva tavoite on toteuttaa `veracrypt_roadmap.md`-tiedoston kohdan **6. Askeleittainen toteutussuunnitelma (Action Plan)** vaiheet 1–11 järjestyksessä. Jokaisen vaiheen hyväksymiskriteerit pitää todentaa koonnilla, testeillä tai muulla kyseiseen kriteeriin suoraan sopivalla näytöllä. Vaiheita 9–11 ei saa avata ennen vaiheen 8 turvaporttien täyttymistä.

## 2. Tiivis vaihetilanne

| Vaihe | Tila | Täsmennys |
|---|---|---|
| 1. Lähtötilanne ja kyvykkyysrajaus | **Valmis** | Julkinen kyvykkyysrajaus, read-only-linja ja turvallisuusrajat on dokumentoitu. Julkiset kirjoitus-, luonti-, FUSE- ja NTFS-polut sekä kuollut mutaatiokoodi on poistettu. |
| 2. Build-, CI- ja release-perusta | **Valmis ja testattu** | Release-allekirjoitus käyttää vain neljää vaadittua ympäristömuuttujaa. Debug toimii ilman niitä, allekirjoitettu release on rakennettu ja verifioitu, ja puuttuvien muuttujien fail-fast-käytös on testattu sekä kaikki muuttujat puuttuvina että vain alias puuttuvana. |
| 3. Session- ja elinkaarimalli | **Koodi valmis, laitetason portti avoin** | Opaque native -session handle, tiedostokuvauksen duplikointi, Kotlinin `ContainerSession`-hallinta, sulkeminen ja peruutuspolut on toteutettu. Instrumentaatiotestit kääntyvät, mutta niitä ei ole voitu ajaa tässä ympäristössä ilman KVM:ää. |
| 4. Kryptopolku ja header-validointi | **Osittain valmis** | KAT-testit, salaisuuksien RAII-nollaus, tarkistetut kokonaislukulaskut ja virhepolkujen kovennus on toteutettu. Virallista VeraCrypt-korpusta ja molempien ABI:en runtime-näyttöä ei ole. Ei-AES-algoritmin yksiselitteinen `unsupported`-luokittelu on yhä ratkaisematta, koska salattua headeria ei voi erottaa väärästä salasanasta ilman kyseisen algoritmin toteutusta. |
| 5. FAT32 read-only | **Paikallinen toteutus valmis, interop-portti avoin** | Moniklusteriset tiedostot/hakemistot, ketjuvalidointi, bounds-tarkistukset ja fuzz/regressiot on toteutettu. Virallisella VeraCryptilla luodun FAT32-säiliön runtime-yhteensopivuus puuttuu. |
| 6. exFAT read-only | **Paikallinen toteutus valmis, interop-portti avoin** | Fragmentoituneet ketjut, entry-set-validointi, 64-bittiset tiedostokoot ja korruptoituneiden/lyhyiden ketjujen hylkäys on toteutettu. Virallinen VeraCrypt-exFAT-interop ja aidon yli 4 GiB tiedoston laitetason metadata-/lukuvarmennus puuttuvat. |
| 7. SAF-provider ja käyttöliittymän turvallisuus | **Koodi valmis, laitetason portti avoin** | Provider käyttää yhden session snapshotia, tiukkoja mode-tarkistuksia, `CancellationSignal`-peruutusta ja auktoritatiivista lookupia. Ulkoinen viewer, peruutus, unmount ja activity recreate -testit kääntyvät. Runtime-ajo puuttuu KVM-rajoitteen vuoksi. Backup on estetty, `FLAG_SECURE` lisätty ja plaintext-exportiin lisätty varoitus. |
| 8. Kovennus ja auditointiportti | **Paikallinen työ tehty, ulkoinen portti avoin** | Lint-, sanitizer-, fuzz-, CI-, SBOM-, dependency/license- ja secret-scan-polut on lisätty. Riippumaton kryptografia-/native-auditointi, auditin P0/P1-löydösten sulkeminen ja branch protection ovat ulkoista tilaa eivätkä ole vielä todennettuja. |
| 9–11. Mutaatiovaiheet | **Ei aloitettu – tarkoituksella lukittu** | Suunnittelu on tiedostossa `docs/FUTURE_MUTATION_DESIGN.md`. Toteutusta ei saa aloittaa ennen kuin vaihe 8 on kokonaan hyväksytty. |

## 3. Vaiheen 2 viimeinen valmistunut tarkistus

Tämän työjakson alussa viimeisteltiin aiemmin kesken jäänyt yhden puuttuvan signing-muuttujan fail-fast-testi komennolla:

```bash
env GRADLE_USER_HOME=/tmp/veracrypt-gradle \
  VERACRYPT_KEYSTORE_PATH=/tmp/veracrypt-release-test.jks \
  VERACRYPT_KEYSTORE_PASSWORD=testpass123 \
  VERACRYPT_KEY_ALIAS= \
  VERACRYPT_KEY_PASSWORD=testpass123 \
  ./gradlew --no-daemon :app:assembleRelease --stacktrace
```

Sandbox-ajo ei päässyt Gradlen konfigurointiin paikallisen socket-rajoituksen vuoksi. Sama komento ajettiin sallituin korotetuin oikeuksin ja se päättyi odotetusti exit-koodiin 1 täsmälleen virheellä:

```text
Release signing requires environment variables: VERACRYPT_KEY_ALIAS
```

Virhe ei nimennyt mitään muuta muuttujaa. Tämä täydentää vaiheen 2 hyväksymisnäytön.

Release-allekirjoituksen aiempi näyttö:

- `app/build.gradle.kts` lukee `System.getenv()`-kutsulla muuttujat `VERACRYPT_KEYSTORE_PATH`, `VERACRYPT_KEYSTORE_PASSWORD`, `VERACRYPT_KEY_ALIAS` ja `VERACRYPT_KEY_PASSWORD`.
- Tyhjät ja `null`-arvot tarkistetaan ennen signingConfigin soveltamista.
- Debug-koonti toimii ilman release-muuttujia.
- Oikeilla testiavaimen arvoilla release-koonti onnistui.
- Android SDK:n `apksigner` vahvisti APK:n v2-allekirjoituksen ja yhden allekirjoittajan.
- Verifioidun APK:n SHA-256 oli `bc5ee1d572a36d00753608b1031792914f93d9af4ad1c879de54609a7cff2e69`.
- Kaikki neljä muuttujaa tyhjinä fail-fast-virhe listasi kaikki neljä nimeä.

## 4. Viimeisin koko koonti- ja testimatriisi

Vaiheen 2 jälkeen ajettiin nykyiselle työpuulle:

```bash
env GRADLE_USER_HOME=/tmp/veracrypt-gradle ./gradlew --no-daemon \
  :app:lintDebug \
  :core-native:lintDebug \
  :provider-saf:lintDebug \
  :app:assembleDebug \
  :core-native:assembleAndroidTest \
  :app:assembleDebugAndroidTest \
  :core-api:test \
  :app:testDebugUnitTest \
  --stacktrace
```

Lopputulos oli:

```text
BUILD SUCCESSFUL in 1m 55s
257 actionable tasks: 32 executed, 2 from cache, 223 up-to-date
```

Tämä todentaa nykyiselle työpuulle debug-APK:n, app- ja native-instrumentaatio-APK:t, kaikkien kolmen moduulin lintin sekä JVM-yksikkötestit. Käynnissä ollutta prosessia ei jäänyt taustalle; tulos ehti valmistua onnistuneesti ennen keskeytyspyyntöä.

## 5. Jo toteutetut olennaiset muutokset

- `SUPPORTED_FEATURES.md`, `SECURITY.md` ja README rajaavat tuotteen read-only-katselimeksi.
- Julkiset kirjoitus-, säiliönluonti-, FUSE- ja NTFS-rajapinnat sekä `#if 0` -mutaatiokoodi on poistettu.
- CI käyttää SHA-pinnattuja actioneita ja sisältää build-, lint-, test-, release-signing-, SBOM-, riippuvuus-, lisenssi- ja salaisuustarkistuksia.
- Native-sessionit ovat opaque handleja, omistavat duplikoidun fd:n ja sulkeutuvat hallitusti.
- Arkaluonteiselle muistille on RAII-nollaus, kryptografiset known-answer-testit ja tarkistetut offset-/kokolaskut.
- FAT32- ja exFAT-parserit ovat read-only, ketju- ja bounds-validoituja sekä tukevat sisäkkäistä navigointia ja 64-bittisiä kokoja.
- Yhteinen puhdas parserikerros on tiedostoissa `filesystem_validation.h/.cpp`.
- Host-fuzzerit ovat `core-native/fuzz/`-hakemistossa: `bpb_fuzzer`, `fat_fuzzer` ja `directory_fuzzer`.
- Kaikki kolme fuzzeria ovat läpäisseet paikallisesti 50 000 ajoa ASan/UBSan-käännöksellä. LSan poistettiin vain paikallisessa ajossa ptrace-rajoitteen vuoksi.
- Host CTest -regressiotesti läpäisi tuloksella 1/1.
- FAT-fixture on 192 KiB ja moniklusterinen; exFAT-fixture sisältää fragmentoituneen ketjun 6 → 8 → EOC.
- Fixture-dokumentaatio ja riippumattoman auditoinnin handoff ovat tiedostoissa `docs/FIXTURE_PROVENANCE.md` ja `docs/INDEPENDENT_AUDIT_HANDOFF.md`.
- SAF-providerin race-, cancellation-, unmount- ja recreate-polkuja on kovennettu ja testit lisätty.
- Android-backup on estetty, arkaluonteiset activityt käyttävät `FLAG_SECURE`-lippua ja plaintext-viennistä varoitetaan.

Fixture-hashit:

- `test.vc`: `b030a4...35f1`
- FAT: `cf1e005...e8a20`
- exFAT: `cc1f6a...94648`

Täydelliset hashit ja alkuperät löytyvät fixture-provenienssidokumentista; yllä olevia lyhenteitä ei pidä käyttää automaattisessa verifioinnissa.

## 6. Tiedossa olevat avoimet tekniset aukot

1. Android-instrumentaatiotestien runtime-ajo puuttuu. Paikallisessa ympäristössä ei ole KVM:ää, ja aiempi software-emulaattoriyritys epäonnistui. APK:t kuitenkin kääntyvät.
2. Virallisella VeraCryptilla luotua, tiedostojärjestelmän sisältävää FAT32-/exFAT-testikorpusta ei ole käytettävissä. Vanha virallinen testiarkisto palautti 404:n.
3. Cryptsetupin `/tmp`-hakemistoon aiemmin ladattu `tcrypt-images.tar.xz` ei kelpaa tiedostojärjestelmäinteroperabiliteetin näytöksi: paketin README kertoo datalohkojen olevan pyyhittyjä.
4. Molempien tuettujen ABI:en (`arm64-v8a`, `x86_64`) laitetason runtime-näyttö puuttuu.
5. Ei-AES-VeraCrypt-headerin erottaminen väärästä salasanasta ei ole yksiselitteisesti mahdollista ilman vaihtoehtoisen salausalgoritmin toteutusta. Hyväksymiskriteeriä ei pidä merkitä täyttyneeksi epäsuoran testin perusteella.
6. Riippumatonta turvallisuusauditointia ei ole tehty, joten vaihe 8 ei ole kokonaisuutena valmis.
7. Branch protection ja ulkoisen auditin P0/P1-löydösten sulkeminen vaativat repository-/auditointipalvelun ulkoista tilaa.

## 7. Täsmällinen jatkojärjestys

Seuraavalla kerralla jatketaan tästä järjestyksestä:

1. Aja native-sanitizer-koonti nykyiselle työpuulle:

   ```bash
   env GRADLE_USER_HOME=/tmp/veracrypt-gradle ./gradlew --no-daemon \
     :core-native:assembleDebug \
     -PveracryptSanitizers=true \
     --stacktrace
   ```

2. Rakenna ja aja host-regressiot sekä kaikki kolme fuzzeria uudelleen nykyistä työpuuta vasten. Käytä ASan/UBSan-käännöstä ja vähintään aiempaa 50 000 ajon tasoa. Älä tulkitse LSanin ympäristörajoitetta ohjelmavirheeksi ilman erillistä näyttöä.
3. Aja `git diff --check`, validoi workflow-YAML ja tee read-only-haku, joka todentaa ettei julkisia write/create/FUSE/NTFS-rajapintoja tai kuollutta mutaatiokoodia ole palannut.
4. Auditoi `veracrypt_roadmap.md`:n vaiheiden 1–8 jokainen hyväksymiskriteeri yksi kerrallaan. Kirjaa jokaiselle suora näyttö; luokittele puuttuva tai epäsuora näyttö avoimeksi.
5. Korjaa kaikki auditissa löytyvät paikallisesti ratkaistavat aukot ja aja muutoksen riskiin sopivat koonnit/testit uudelleen.
6. Hanki tai tuota erillisessä, luotetussa VeraCrypt Desktop -ympäristössä oikeat FAT32- ja exFAT-säiliöt dokumentoidulla VeraCrypt-versiolla. Lisää vain redistribuutioltaan sallittu korpus ja täydet SHA-256-hashit.
7. Aja instrumentaatiotestit kahdella ABI:lla oikeassa laitteessa tai KVM-kiihdytetyssä emulaattorissa. Todennettava vähintään mount/open/read/seek/close, peruutus, unmount, recreate, fragmentoitunut exFAT, moniklusterinen FAT32 sekä yli 4 GiB exFAT-metatieto.
8. Toimita `docs/INDEPENDENT_AUDIT_HANDOFF.md` riippumattomalle tarkastajalle. Sulje kaikki P0/P1-löydökset ja varmista branch protection.
9. Vasta kun kohdat 6–8 ja kaikki vaiheen 8 hyväksymiskriteerit on todistettu, päivitä vaiheen 8 tila valmiiksi ja aloita vaihe 9. Muussa tapauksessa vaiheet 9–11 pysyvät lukittuina.

## 8. Työpuuta koskevat varotoimet

- Työpuussa on laaja, tarkoituksellinen toteutusmuutos. Älä käytä `git reset --hard`-, `git checkout --`- tai muuta käyttäjän muutoksia hävittävää komentoa.
- Säilytä kaikki asiaan kuulumattomat käyttäjän muutokset.
- Käytä tiedostomuutoksiin `apply_patch`-menetelmää.
- Gradle tarvitsee tässä ympäristössä tyypillisesti sandboxin ulkopuolisen oikeuden paikallisen daemon-socketin vuoksi. Sandboxissa näkyvä `java.net.SocketException: Operation not permitted` ei ole projektin koontivirhe.
- `/tmp/veracrypt-release-test.jks` oli tämän työjakson aikana olemassa; alias oli `veracrypt-test` ja testiavaimen salasanat `testpass123`. `/tmp` ei ole pysyvä tallennus, joten tiedoston olemassaolo on tarkistettava ennen seuraavaa release-testiä.
- Älä koskaan tallenna oikeita release-salaisuuksia repositoryyn tai `local.properties`-tiedostoon.

## 9. Valmiuden tulkinta

Vaiheet 1 ja 2 voidaan tällä hetkellä merkitä valmiiksi. Vaiheiden 3–7 toteutus on pitkällä tai paikallisesti valmis, mutta niiden roadmap-tason hyväksyntää ei saa väittää täydelliseksi ilman puuttuvaa laite- ja virallista interoperabiliteettinäyttöä. Vaihe 8 on ulkoisen auditointiportin vuoksi avoin. Tästä seuraa, että koko vaiheiden 1–11 tavoite ei ole vielä valmis eikä vaiheita 9–11 pidä aloittaa.
