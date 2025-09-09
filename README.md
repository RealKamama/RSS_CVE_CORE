# Automatisierter RSS/Atom-Feed-Aggregator für PostgreSQL

## 1.0 Übersicht

Dieses Projekt implementiert eine robuste und erweiterbare Datenpipeline, die darauf ausgelegt ist, Inhalte von syndizierten Web-Feeds systematisch zu sammeln und zu archivieren. Die Kernfunktionalität besteht darin, Einträge aus einer konfigurierbaren Liste von RSS-, Atom- oder anderen gängigen Feed-Formaten abzurufen und diese strukturiert in einer PostgreSQL-Datenbank zu speichern.

Die Architektur des Projekts folgt dem etablierten ETL-Muster (Extract, Transform, Load), einem fundamentalen Konzept in der Datenverarbeitung und im Data Warehousing.

  * **Extract (Extrahieren):** In dieser Phase nutzt die Anwendung die leistungsstarke `feedparser`-Bibliothek, um Daten von externen Web-Quellen abzurufen.[1] `feedparser` normalisiert die verschiedenen Feed-Formate in eine einheitliche, verarbeitbare Struktur.
  * **Transform (Transformieren):** Die extrahierten Rohdaten werden anschließend verarbeitet. In dieser (impliziten) Phase werden relevante Datenpunkte wie Titel, Link, Veröffentlichungsdatum und Beschreibung aus der normalisierten Struktur extrahiert und für die Speicherung vorbereitet.
  * **Load (Laden):** In der letzten Phase werden die transformierten Daten mithilfe des `psycopg2`-Adapters, dem De-facto-Standard für die Python-PostgreSQL-Kommunikation, sicher und effizient in die Zieldatenbank geladen.[2, 3]

Durch die klare Trennung dieser Phasen ist das System modular und wartbar. Hauptanwendungsfälle umfassen die Aggregation von Nachrichten, die Überwachung von Branchen-Blogs, die Archivierung von wissenschaftlichen Veröffentlichungen oder die Bereitstellung eines kuratierten Datenstroms für nachgelagerte Analysewerkzeuge und Applikationen.

## 2.0 Kerntechnologien

Die Stabilität und Funktionalität dieses Projekts basiert auf einer sorgfältig ausgewählten Gruppe von branchenüblichen Open-Source-Technologien. Jede Komponente wurde aufgrund ihrer Zuverlässigkeit, Leistungsfähigkeit und umfassenden Dokumentation gewählt.

### Python 3

Python dient als primäre Programmiersprache für die gesamte Anwendungslogik. Seine klare Syntax, die umfangreiche Standardbibliothek und das reichhaltige Ökosystem an Drittanbieter-Paketen machen es zur idealen Wahl für die schnelle Entwicklung von Datenverarbeitungs-Pipelines. Dieses Projekt erfordert eine Python-Version von 3.8 oder höher, um die Kompatibilität mit allen Abhängigkeiten zu gewährleisten.[4]

### Feedparser

`feedparser` ist eine universelle Python-Bibliothek zum Herunterladen und Parsen von syndizierten Feeds. Ihre herausragende Eigenschaft ist die Fähigkeit, eine beeindruckende Vielfalt an Formaten nahtlos zu verarbeiten, darunter RSS (Versionen 0.90 bis 2.0), Atom (0.3 und 1.0), RDF und CDF.[5, 6]

Die zentrale Funktion der Bibliothek ist `feedparser.parse()`. Diese Methode ist äußerst flexibel und kann ihre Eingabe von einer Remote-URL, einer lokalen Datei oder sogar direkt aus einem String im Speicher beziehen.[5, 7] Der entscheidende Mehrwert von `feedparser` liegt in der Normalisierung: Unabhängig vom Format des Eingabe-Feeds gibt die `parse()`-Funktion eine konsistente Python-Wörterbuchstruktur zurück. Dies vereinfacht die Extraktion von Metadaten und Einträgen erheblich. Allgemeine Informationen über den Feed (wie der Titel) sind über den Schlüssel `feed` zugänglich (z.B. `d['feed']['title']`), während die einzelnen Artikel oder Beiträge als eine Liste von Wörterbüchern unter dem Schlüssel `entries` verfügbar sind (z.B. `d['entries']['link']`).[1, 7] Diese Abstraktion macht den Extraktionscode robust gegenüber den Inkonsistenzen und Variationen, die in der realen Welt der Web-Feeds üblich sind.

### Psycopg 2 (via `psycopg2-binary`)

`psycopg2` ist der am weitesten verbreitete und ausgereifteste PostgreSQL-Datenbankadapter für Python. Er bietet eine vollständige Implementierung der Python Database API Specification v2.0 und gewährleistet so eine standardisierte und vertraute Schnittstelle für Datenbankinteraktionen.[2, 3]

Die Bibliothek fungiert als hocheffiziente Brücke zwischen der Python-Anwendung und dem PostgreSQL-Server. Da sie größtenteils in C als Wrapper um die offizielle `libpq`-Client-Bibliothek von PostgreSQL implementiert ist, bietet sie eine hervorragende Leistung und Sicherheit.[2, 8] `psycopg2` ist für stark nebenläufige Anwendungen konzipiert, die eine große Anzahl von Datenbankverbindungen und -transaktionen verwalten müssen.[3] Sie ermöglicht das sichere Übergeben von Parametern an SQL-Abfragen (was SQL-Injection-Angriffe verhindert), die Steuerung von Transaktionen (Commit/Rollback), die Nutzung von serverseitigen Cursorn für die effiziente Verarbeitung großer Datenmengen und eine flexible Anpassung von Python-Datentypen an entsprechende PostgreSQL-Typen.[3] Für dieses Projekt wird zunächst die `psycopg2-binary`-Variante verwendet, die den Einstieg erleichtert, indem sie vorkompilierte Binärdateien bereitstellt und komplexe Build-Schritte überflüssig macht.[9]

## 3.0 Features

Dieses Projekt bietet eine Reihe von leistungsstarken Funktionen, die direkt aus den Fähigkeiten seiner Kerntechnologien abgeleitet sind.

  * **Umfassende Feed-Kompatibilität:** Dank `feedparser` verarbeitet das System mühelos eine breite Palette von syndizierten Feed-Formaten, einschließlich aller gängigen Versionen von RSS, Atom und RDF. Dies gewährleistet maximale Reichweite bei der Datenerfassung.[5, 6]
  * **Strukturierte Datenspeicherung:** Die Pipeline wandelt die semi-strukturierten Informationen aus den Feeds in ein vollständig strukturiertes, relationales Format um. Die Speicherung in einer PostgreSQL-Datenbank ermöglicht komplexe Abfragen, Aggregationen und Analysen der gesammelten Daten.
  * **Flexible Konfiguration:** Die gesamte Konfiguration, einschließlich der Datenbankverbindung und der Liste der zu überwachenden Feeds, erfolgt über Umgebungsvariablen. Dieser Ansatz folgt den "Twelve-Factor App"-Prinzipien und ermöglicht eine einfache Anpassung für verschiedene Umgebungen (Entwicklung, Staging, Produktion), ohne dass Code-Änderungen erforderlich sind.
  * **Skalierbarkeit:** Die Architektur ist von Natur aus skalierbar. Die Anzahl der zu verarbeitenden Feeds kann durch einfaches Hinzufügen weiterer URLs zur Konfiguration erhöht werden. Die Verwendung von PostgreSQL als Backend stellt sicher, dass das System auch mit sehr großen Datenmengen effizient umgehen kann.
  * **Grundlage für Erweiterungen:** Die Wahl der Technologien legt den Grundstein für zukünftige Erweiterungen. Das robuste Datenbankschema kann problemlos erweitert werden, um zusätzliche Metadaten wie Autoreninformationen, Kategorien oder sogar den vollständigen Artikelinhalt zu speichern. Die Transformationslogik in Python kann ausgebaut werden, um anspruchsvollere Aufgaben wie Keyword-Extraktion, Sentiment-Analyse oder die Deduplizierung von Einträgen durchzuführen. Damit ist dieses Projekt nicht nur ein einfacher Aggregator, sondern eine solide Basis für komplexere Datenanalyse- und Content-Management-Systeme.

## 4.0 Systemanforderungen

Bevor Sie mit der Installation beginnen, stellen Sie bitte sicher, dass die folgenden Softwarekomponenten auf Ihrem System vorhanden und konfiguriert sind:

  * **Python:** Version 3.8 oder eine neuere Version ist erforderlich. Die Kompatibilität mit den Kernabhängigkeiten, insbesondere `psycopg2`, ist ab dieser Version gewährleistet.[4] Sie können Ihre installierte Version mit dem Befehl `python3 --version` überprüfen.
  * **PostgreSQL-Datenbank:** Sie benötigen Zugriff auf eine laufende PostgreSQL-Instanz. `psycopg2` ist mit PostgreSQL-Serverversionen von 7.4 bis 17 kompatibel, wobei eine neuere Version (ab 9.1) empfohlen wird.[4] Dies kann eine lokale Installation, ein Docker-Container oder ein verwalteter Cloud-Dienst (z. B. Amazon RDS, Google Cloud SQL, ElephantSQL) sein.
  * **Python Paketmanager:** Die Werkzeuge `pip` (für die Installation von Paketen) und `venv` (für die Erstellung von isolierten Umgebungen) müssen verfügbar sein. Diese sind in den meisten modernen Python-Distributionen standardmäßig enthalten.
  * **Git:** Das Versionskontrollsystem Git wird benötigt, um den Quellcode des Projekts aus dem Repository zu klonen.

## 5.0 Installation und Einrichtung
Ich nutze **Docker**.

```bash
docker-compose up --build -d
```

Nach Abschluss dieser Schritte ist die Anwendung installiert und bereit für die Konfiguration.

## 6.0 Konfiguration

Die Anwendung wird ausschließlich über Umgebungsvariablen konfiguriert. Dieser Ansatz ist eine bewährte Methode, um sensible Informationen wie Datenbank-Anmeldeinformationen von der Codebasis getrennt zu halten und die Portabilität der Anwendung zwischen verschiedenen Umgebungen zu erleichtern.

Für die lokale Entwicklung ist es am einfachsten, eine Datei mit dem Namen `.env` im Stammverzeichnis des Projekts zu erstellen. Diese Datei wird (sofern ein entsprechendes Hilfsprogramm wie `python-dotenv` verwendet wird) automatisch geladen, um die Umgebungsvariablen zu setzen.

**Wichtiger Sicherheitshinweis:** Fügen Sie die `.env`-Datei unbedingt zu Ihrer `.gitignore`-Datei hinzu, um zu verhindern, dass sie versehentlich in die Versionskontrolle eingecheckt wird.

**Beispiel für eine `.env`-Datei liegt bei**


