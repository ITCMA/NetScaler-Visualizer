# Rechtliche Hinweise

🇬🇧 [English version](LEGAL.md)

Diese Hinweise beschreiben, wie das Projekt mit Marken, Drittkomponenten, Normverweisen und Kundendaten umgeht. Sie dienen
der Information der Anwender und sind keine Rechtsberatung.

## Marken
NetScaler und Citrix sind Marken der jeweiligen Rechteinhaber. Dieses Projekt ist ein unabhängiges Werkzeug. Es ist weder mit
den Markeninhabern verbunden noch von ihnen unterstützt oder empfohlen; die Namen dienen nur dazu, die Produkte zu benennen,
mit denen das Werkzeug arbeitet. Der Hinweis steht im README, auf der Startseite der lokalen Oberfläche, in der Übersicht des
Reports und im Hilfedialog. Das Projekt verwendet keine Logos, Farben oder Grafiken der Markeninhaber.

## Drittkomponenten
- Der Report bettet Cytoscape.js, dagre und cytoscape-dagre (MIT-Lizenz) ein. Urheberrechts- und Lizenzhinweise liegen in
  `nsviz/assets/vendor/` und in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
- Optionale Beispiel-Konfigurationen stammen aus einem Drittprojekt unter der Apache License 2.0. Sie sind nicht Teil dieses
  Repositorys und werden auf Wunsch auf dem Rechner des Anwenders geladen ([SOURCES.de.md](SOURCES.de.md)).
- Herstellerdokumentation wird nicht kopiert. Die Regeltexte sind eigenständig formuliert und nennen ihre Quellen.

## Verweise auf Normen und Herstellerhinweise
Regeln verweisen auf Bausteine des BSI IT-Grundschutzes, die BSI TR-02102-2 und die Secure-Deployment-Hinweise des Herstellers
auf Themenebene, ohne Anforderungs-IDs. Die Zuordnung ist eine fachliche Einordnung. Vor der Verwendung in einem Audit ist sie
gegen die aktuelle Fassung des jeweiligen Dokuments zu prüfen. Das Werkzeug bescheinigt keine Konformität; die Kategorie heißt
„Compliance-Hinweise“.

## Kundendaten und Datenschutz
Konfigurationen können personenbezogene Daten enthalten, etwa Benutzernamen, E-Mail-Adressen, IP-Adressen und LDAP-Namen, und
sind für den Kunden vertraulich. Die Verarbeitung im Auftrag eines Kunden sollte dem Projektvertrag, einer etwaigen
Geheimhaltungsvereinbarung und gegebenenfalls einem Auftragsverarbeitungsvertrag folgen. Das Werkzeug verarbeitet alles lokal;
das Konzept zum Umgang steht in [PRIVACY.de.md](PRIVACY.de.md). Die Maskierung von Secrets ist musterbasiert und keine Garantie.

## Gewährleistung und Haftung
Die Software wird „wie besehen“ bereitgestellt (siehe [LICENSE](../LICENSE)). Ergebnisse sind automatisierte Hinweise.
Empfehlungen an Kunden bleiben in der fachlichen Verantwortung des Anwenders.

## Rechte
Copyright (c) 2026 ITCMA GmbH. Alle Rechte vorbehalten. Ohne schriftliche Erlaubnis des Rechteinhabers wird keine Lizenz zur
Nutzung, Vervielfältigung, Änderung oder Verbreitung erteilt.
