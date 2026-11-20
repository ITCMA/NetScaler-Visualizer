# Rechtliche Hinweise (Hinweise, keine Rechtsberatung)

🇬🇧 [English version](LEGAL.md)

Dies ist eine fachliche Checkliste von Punkten, die geprüft werden sollten. Sie ist **keine Rechtsberatung** und trifft keine verbindlichen Aussagen.
Für Verbindliches (Veröffentlichung, kommerzielle Nutzung, Kundenverträge) eine juristische Prüfung einholen.

## 1. Marken und Projektname – *höchstes Risiko*
- „NetScaler“ und „Citrix“ sind Marken der jeweiligen Rechteinhaber (zu verifizieren: derzeit Cloud Software Group, Inc. bzw. verbundenen
  Unternehmen zugeordnet). Report, README und Lizenz weisen darauf hin, dass das Projekt unabhängig und weder verbunden noch empfohlen ist.
- Ein Disclaimer macht die Nutzung einer Marke nicht allein zulässig. Beschreibende Verwendung („Analysewerkzeug *für* NetScaler“) wird
  meist eher toleriert als die Marke als **Produktname** („NetScaler Visualizer“), als Repository-/Domain-/Paketname oder mit Logos. Ob und wie das
  zulässig ist, hängt von der Rechtsordnung und den Markenrichtlinien des Inhabers ab – nicht verifiziert.
- Das Risiko steigt, wenn das Projekt öffentlich oder kommerziell ist oder Logos/Farben/Produktgrafiken des Inhabers nutzt (tut es nicht).
- **Vorschlag:** neutralen Produktnamen verwenden und die Marke nur beschreibend nennen, z. B. *„<NeutralerName> – Konfigurationsanalyse für NetScaler ADC“*.
  Mögliche Muster: neutrale ADC-bezogene Namen (z. B. „adc-config-map“, „adcscope“, „confgraph“) – **Verfügbarkeit nicht geprüft**; vor der Wahl
  Markenregister (DPMA, EUIPO, USPTO) sowie Paket- und Domainnamen prüfen. Python-Paket `nsviz` und CLI-Name sind bereits neutral; Repository-Name
  und Report-Titel enthalten derzeit „NetScaler“.
- Aktuelle Marken-/Brand-Richtlinien des Inhabers für Drittwerkzeuge prüfen.

## 2. Drittanbieter-Lizenzen
- Eingebettete Bibliotheken (Cytoscape.js, dagre, cytoscape-dagre) stehen unter MIT: Urheberrechts- und Lizenzhinweise beibehalten
  (erledigt in `nsviz/assets/vendor/` und `THIRD_PARTY_NOTICES.md`). Der minifizierte dagre-Build enthält graphlib und lodash; deren genaue Versionen und
  Hinweise sind noch zu erfassen.
- Die Testdaten stammen aus einem Drittprojekt unter Apache-2.0 und werden **nicht weiterverteilt** (Download auf dem Rechner des Nutzers).
  Bei einer Weitergabe: Lizenztext, ggf. Upstream-NOTICE beilegen und Änderungen kennzeichnen (Hex-Blobs genullt).
  Die Herkunft der Inhalte dieser Dateien ist nicht verifiziert.
- Herstellerdokumentation und Support-Artikel sind urheberrechtlich geschützt: es wird kein Text übernommen; Regeltexte sind eigene Formulierungen mit Quellenverweis.

## 3. Normverweise (BSI)
- Die Verweise nennen BSI-IT-Grundschutz-Bausteine und BSI TR-02102-2 auf Themenebene, keine Anforderungs-IDs, und sind **nicht** gegen die aktuellen
  Ausgaben verifiziert. Vor Audit-Nutzung: gegen die aktuelle Edition prüfen, Edition und Anforderungs-IDs korrekt zitieren und BSI-Text nicht über
  kurze Zitate mit Quellenangabe hinaus wiedergeben.
- Das Werkzeug bescheinigt keine Konformität. Aussagen wie „BSI-konform“ vermeiden; die Kategorie heißt „Compliance-*Hinweise*“.

## 4. Datenschutz (DSGVO) und Vertraulichkeit
- Configs können personenbezogene Daten enthalten (Benutzer-/Adminnamen, E-Mail-Adressen, IPs, LDAP-DNs) und sind für den Kunden geschäftlich vertraulich.
  Die Verarbeitung erfolgt im Auftrag des Kunden: Projektvertrag/NDA und ggf. Auftragsverarbeitungsvertrag prüfen.
- Siehe [PRIVACY.de.md](PRIVACY.de.md): lokale Verarbeitung, git-ignorierter privater Ordner, Anonymisierung vor jeder Entwicklungsnutzung, Aufbewahrung/Löschung.
- Die Maskierung von Geheimnissen ist musterbasiert und keine Garantie.

## 5. Haftung und Gewährleistung
- Der Lizenztext schließt Gewährleistung und Haftung aus („as is“). Nach deutschem Recht kann die Haftung für Vorsatz nicht im Voraus ausgeschlossen werden,
  Begrenzungen für andere Fälle hängen vom Vertragstyp ab – der Wortlaut muss für den vorgesehenen Einsatz geprüft werden. Ergebnisse sind automatisierte Hinweise;
  Empfehlungen gegenüber Kunden bleiben in der fachlichen Verantwortung des Consultants.

## 6. Inhaberschaft und Lizenzmodell
- Derzeit „alle Rechte vorbehalten“, keine Open-Source-Lizenz. Klären, wer die Rechte hält (Autor vs. Arbeitgeber/Firma; Arbeitsvertrag,
  Nebentätigkeitsregeln) und ob Kunden Nutzungsrechte erhalten dürfen (Lizenz für Arbeitsergebnisse).
- Vor einer Veröffentlichung von Code, den andere weiterverwenden dürfen, bewusst über eine Lizenz entscheiden.

## 7. Weitere Punkte für eine juristische Prüfung
- Export verschlüsselungsbezogener Inhalte: für das Werkzeug selbst nicht einschlägig; es implementiert keine Kryptografie.
- Pflichten gegenüber Kunden/Arbeitgebern zu Werkzeugen für Arbeitsergebnisse (Offenlegung, Sicherheitsanforderungen) – Verträge prüfen.
- Barrierefreiheitspflichten können bei kommerziellem Angebot gelten (z. B. EU-Vorgaben); die Oberfläche folgt üblicher Praxis
  (Tastatur, Kontrast, ARIA), hat aber kein formales Konformitätsaudit.
