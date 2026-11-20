# Prüfregeln

Automatisch erzeugt mit `python -m nsviz rules --markdown --lang de`. Jede Regel hat Schweregrad, Kategorie und eine **Sicherheit der Aussage** (`certain` = eindeutig aus der Config ableitbar, `likely` = übliche Annahme, `heuristic` = Näherung, bitte im Einzelfall prüfen).

> Die Verweise auf BSI-Bausteine und die Secure-Deployment-Hinweise des Herstellers nennen den Baustein bzw. das Thema, **nicht** einzelne Anforderungs-IDs. Das Mapping ist als fachliche Einordnung gedacht und sollte vor Verwendung in einem Audit gegen die jeweils aktuelle Fassung geprüft werden.

## Fehlkonfiguration

### AAA-004 – Gateway ohne Authentifizierung

- **Schweregrad:** high · **Sicherheit der Aussage:** likely
- **Begründung:** `-authentication OFF` erlaubt anonymen Zugriff; ein Gateway ohne gebundene Auth-Policy/Authn-Profil bietet ebenfalls keine Anmeldung (Annahme: Auth ist nicht über Standard-Authentifizierung/andere Wege geregelt).
- **Behebung:** Auth-Policy binden (`bind vpn vserver <gw> -policy <authpol> -priority 100`) oder `-authnProfile` setzen.
- **Quellen:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement

### HA-003 – Konfigurationsabweichung zwischen HA-Knoten

- **Schweregrad:** high · **Sicherheit der Aussage:** likely
- **Begründung:** Nach dem Abgleich sollten beide Knoten (bis auf knotenspezifische Objekte wie NSIP, Hostname, Interfaces) identisch sein. Abweichungen führen nach Failover zu anderem Verhalten.
- **Behebung:** Sync prüfen (`show ha node`, `force ha sync`), Ursachen klären (manuelle Änderung mit -haProp DISABLED, Sync-Fehler).
- **Quellen:** Citrix/NetScaler documentation: high availability (synchronization)

### QA-007 – Referenz auf nicht vorhandenes Objekt

- **Schweregrad:** high · **Sicherheit der Aussage:** likely
- **Begründung:** Eine Bindung/Option verweist auf ein Objekt, das in der Konfiguration nicht existiert (Tippfehler, unvollständiger Export oder gelöschtes Objekt). Bei Teil-Exports ist das erwartbar — Annahme: Config ist vollständig.
- **Behebung:** Objekt anlegen oder Referenz korrigieren.
- **Quellen:** –

### QA-008 – Doppelte vServer-Adresse (IP:Port)

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Zwei vServer mit derselben IP/Port/Protokoll kollidieren.
- **Behebung:** Eine Adresse ändern.
- **Quellen:** –

### QA-009 – Objekte konfiguriert, aber Feature nicht aktiviert

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Ohne `enable ns feature <X>` sind Objekte der Funktion wirkungslos (und teils nicht anlegbar).
- **Behebung:** `enable ns feature <Feature>`.
- **Quellen:** –

### QA-010 – CS-vServer ohne Ziel

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Ein CS-vServer ohne Default-LB-vServer und ohne Policies verwirft/beantwortet nichts sinnvoll.
- **Behebung:** Default-LB-vServer (`bind cs vserver <cs> <lb>`) und/oder CS-Policies binden.
- **Quellen:** –

### TLS-004 – TLS 1.2 deaktiviert

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Ohne TLS 1.2 bleiben nur veraltete Protokolle (oder nur TLS 1.3).
- **Behebung:** `-tls12 ENABLED`.
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security)

### TLS-008 – SSL-vServer ohne Zertifikat

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Ein TLS-terminierender vServer ohne gebundenes Zertifikat steht auf DOWN bzw. kann keine Handshakes abschließen.
- **Behebung:** `bind ssl vserver <vs> -certkeyName <cert>`.
- **Quellen:** –

### AAA-005 – nFactor: Policy Label ohne Login Schema

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Ein Policy Label ohne `-loginSchema` zeigt keine Eingabefelder; der Faktor kann nur mit `LSCHEMA_INT` (kein UI) sinnvoll sein.
- **Behebung:** `add authentication policylabel <name> -loginSchema <schema>` bzw. bewusst `LSCHEMA_INT` für Pass-through-Faktoren.
- **Quellen:** –

### AAA-007 – Authentifizierungs-vServer ohne Policy

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** Ein authentication vServer ohne gebundene Policy kann niemanden authentifizieren.
- **Behebung:** Auth-Policies mit Priorität binden.
- **Quellen:** –

### GSLB-001 – GSLB-vServer ohne Domain

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** Ohne `bind gslb vserver -domainName` beantwortet der vServer keine DNS-Anfrage.
- **Behebung:** Domain binden.
- **Quellen:** –

### GSLB-002 – GSLB ohne ADNS-Service

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** GSLB-Antworten setzen einen ADNS-Service (oder DNS-Proxy-Betrieb) voraus. Annahme: ADNS wird nicht auf einem anderen Gerät betrieben.
- **Behebung:** `add service <name> <ip> ADNS 53`.
- **Quellen:** –

### HA-001 – HA-Synchronisation/Propagation deaktiviert

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** `-haSync DISABLED` oder `-haProp DISABLED` führt zu Konfigurationsabweichungen zwischen den Knoten.
- **Behebung:** `set ha node -haSync ENABLED -haProp ENABLED`.
- **Quellen:** –

### QA-001 – LB-vServer ohne gebundenen Service

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** Ein LB-vServer ohne Service/Service Group hat kein Backend und ist DOWN.
- **Behebung:** Service/Service Group binden oder vServer entfernen.
- **Quellen:** –

### REP-001 – IP-Reputation-Regeln, aber Feature/Einstellungen fehlen

- **Schweregrad:** medium · **Sicherheit der Aussage:** heuristic
- **Begründung:** Policies mit `IPREP`-Ausdrücken werden nur ausgewertet, wenn das Reputation-Feature aktiv ist (Annahme: Feature-Name `REP`; bei 13.1+ ggf. abweichend benannt) und das Gerät die Reputationsdaten abrufen kann (`set reputation settings`).
- **Behebung:** `enable ns feature REP` und `set reputation settings -proxyServer …` (falls Proxy nötig) prüfen.
- **Quellen:** –

### WAF-001 – WAF-Profil ohne Policy-Bindung

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** Ein AppFW-Profil ohne Policy schützt nichts.
- **Behebung:** `add appfw policy` und an vServer/global binden.
- **Quellen:** BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

### AAA-006 – nFactor: Policy Label nicht erreichbar

- **Schweregrad:** low · **Sicherheit der Aussage:** certain
- **Begründung:** Ein Policy Label, das über keinen `-nextFactor` erreicht wird, ist toter Code.
- **Behebung:** Entfernen oder verknüpfen.
- **Quellen:** –

### QA-002 – Service/Service Group ohne Bindung an einen vServer

- **Schweregrad:** low · **Sicherheit der Aussage:** certain
- **Begründung:** Nicht gebundene Services erzeugen Monitoring-Last und Verwirrung ohne Nutzen.
- **Behebung:** Binden oder entfernen.
- **Quellen:** –

### QA-004 – Policy ohne Bindung

- **Schweregrad:** low · **Sicherheit der Aussage:** certain
- **Begründung:** Eine Policy, die nirgends gebunden ist, hat keine Wirkung.
- **Behebung:** Binden oder entfernen.
- **Quellen:** –

### QA-005 – Zertifikat ohne Verwendung

- **Schweregrad:** low · **Sicherheit der Aussage:** certain
- **Begründung:** Ungenutzte Zertifikate vergrößern die Angriffsfläche und verschleiern Ablaufmonitoring.
- **Behebung:** Entfernen.
- **Quellen:** –

### QA-003 – Server-Objekt ohne Verwendung

- **Schweregrad:** info · **Sicherheit der Aussage:** certain
- **Begründung:** `add server` ohne Service/Service Group.
- **Behebung:** Entfernen, falls nicht mehr benötigt.
- **Quellen:** –

### QA-006 – Monitor ohne Bindung

- **Schweregrad:** info · **Sicherheit der Aussage:** certain
- **Begründung:** Nicht gebundener Monitor.
- **Behebung:** Entfernen oder binden.
- **Quellen:** –

### QA-012 – vServer administrativ deaktiviert

- **Schweregrad:** info · **Sicherheit der Aussage:** certain
- **Begründung:** Deaktivierte vServer bleiben in Configs oft als Altlast.
- **Behebung:** Entfernen, falls dauerhaft unbenötigt.
- **Quellen:** –

## Best Practice

### MGMT-003 – Management-Zugriff auf SNIP/VIP aktiviert

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Verwaltungsdienste (SSH/GUI/SNMP) sollten nur über die NSIP/ein Management-Netz erreichbar sein, nicht über Data-Plane-Adressen.
- **Behebung:** `set ns ip <snip> -mgmtAccess DISABLED -telnet DISABLED -ssh DISABLED -gui DISABLED -snmp DISABLED`; Management-Zugriff nur auf der NSIP, ggf. mit ACLs.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide (section management access/hardening); BSI IT-Grundschutz NET.1.2 Netzmanagement

### TLS-007 – Selbstsigniertes Standardzertifikat am vServer

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** `ns-server-certificate` ist selbstsigniert und gerätespezifisch; Clients können es nicht validieren.
- **Behebung:** Zertifikat einer vertrauenswürdigen CA binden.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide (TLS); BSI IT-Grundschutz CON.1 Kryptokonzept

### TLS-006 – SSL-Neuverhandlung nicht eingeschränkt

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** `-denySSLReneg NO` erlaubt Client-initiierte Renegotiation (DoS-Vektor).
- **Behebung:** `-denySSLReneg FRONTEND_CLIENT` (Standard) oder `ALL`.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide (TLS)

### GSLB-004 – GSLB-Metric-Exchange (MEP) deaktiviert

- **Schweregrad:** low · **Sicherheit der Aussage:** certain
- **Begründung:** Bei mehreren Sites ist ohne MEP keine Last-/Statusinformation zwischen den Sites verfügbar.
- **Behebung:** `-metricExchange ENABLED`.
- **Quellen:** –

### MGMT-006 – Passwortwechsel beim ersten Login nicht erzwungen

- **Schweregrad:** low · **Sicherheit der Aussage:** likely
- **Begründung:** `-forcePasswordChange` zwingt zum Ändern des Default-Kennworts.
- **Behebung:** `set system parameter -forcePasswordChange ENABLED`.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### MGMT-009 – Keine externe Authentifizierung für Administratoren

- **Schweregrad:** low · **Sicherheit der Aussage:** likely
- **Begründung:** Ohne `bind system global <auth-policy>` werden Admins nur lokal geführt (keine zentrale Rechteverwaltung/Nachvollziehbarkeit).
- **Behebung:** LDAP/RADIUS/TACACS+-Policy für die Management-Authentifizierung anlegen und per `bind system global` binden.
- **Quellen:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement

### MGMT-011 – Keine Zeitsynchronisation (NTP)

- **Schweregrad:** low · **Sicherheit der Aussage:** likely
- **Begründung:** Ohne NTP sind Logs/Zertifikatsprüfungen unzuverlässig.
- **Behebung:** `add ntp server <ip>` und `enable ntp sync`.
- **Quellen:** BSI IT-Grundschutz OPS.1.1.5 Protokollierung

### MGMT-013 – SNMP v1/v2c statt SNMPv3 verwendet

- **Schweregrad:** low · **Sicherheit der Aussage:** likely
- **Begründung:** Community-basiertes SNMP kennt weder Verschlüsselung noch starke Authentifizierung.
- **Behebung:** SNMPv3 mit authPriv konfigurieren.
- **Quellen:** BSI IT-Grundschutz NET.1.2 Netzmanagement

### MGMT-014 – HTTP-Härtungsparameter nicht gesetzt

- **Schweregrad:** low · **Sicherheit der Aussage:** heuristic
- **Begründung:** Der Secure Deployment Guide empfiehlt u.a. `set ns httpParam -dropInvalReqs ON` (ungültige HTTP-Requests verwerfen). Konkrete Empfehlung bitte gegen die aktuelle Version des Guides prüfen.
- **Behebung:** `set ns httpParam -dropInvalReqs ON -markHttp09Inval ON -markConnReqInval ON`.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### TLS-005 – TLS 1.3 nicht aktiviert

- **Schweregrad:** low · **Sicherheit der Aussage:** likely
- **Begründung:** TLS 1.3 wird seit NetScaler 12.1 unterstützt und in TR-02102-2 empfohlen. Nur explizit deaktiviertes TLS 1.3 wird gemeldet; fehlende Angaben (Standardwerte hängen von Version/Profil ab) sind eine Annahme.
- **Behebung:** `-tls13 ENABLED`.
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security)

### TLS-009 – Ablaufüberwachung des Zertifikats deaktiviert

- **Schweregrad:** low · **Sicherheit der Aussage:** certain
- **Begründung:** Mit `-expiryMonitor DISABLED` gibt es keine Warnung vor Ablauf. Das tatsächliche Ablaufdatum steht nicht in der ns.conf und kann hier nicht geprüft werden.
- **Behebung:** `set ssl certKey <ck> -expiryMonitor ENABLED -notificationPeriod 30`.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide (TLS)

### TLS-011 – Kein HSTS konfiguriert

- **Schweregrad:** low · **Sicherheit der Aussage:** heuristic
- **Begründung:** Ohne HTTP-Strict-Transport-Security-Header können Browser auf HTTP zurückfallen.
- **Behebung:** Rewrite-Policy mit `Strict-Transport-Security` oder `-HSTS ENABLED` im SSL-Profil.
- **Quellen:** BSI IT-Grundschutz APP.3.2 Webserver / APP.3.1 Webanwendungen und Webservices

### WAF-002 – WAF-Profil ohne blockierende Aktion

- **Schweregrad:** low · **Sicherheit der Aussage:** heuristic
- **Begründung:** Ohne `block` in einer der Check-Aktionen läuft das Profil faktisch nur im Beobachtungsmodus. Heuristik: es werden alle `...Action`-Optionen des Profils geprüft; Defaults aus `-defaults basic/advanced` sind nicht aufgelöst.
- **Behebung:** Checks im Lernmodus validieren, danach `block log stats` setzen.
- **Quellen:** BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

### CHAIN-001 – Double-Hop: Zuordnung nur über IP

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Backend-Ziel stimmt mit einer Frontend-Adresse des nachgelagerten NetScalers nur in der IP, nicht im Port überein (z.B. Port-Mapping/NAT dazwischen). Zuordnung ist eine Annahme.
- **Behebung:** Zuordnung manuell prüfen.
- **Quellen:** –

### GSLB-003 – GSLB-vServer mit weniger als zwei Services

- **Schweregrad:** info · **Sicherheit der Aussage:** certain
- **Begründung:** Ein GSLB-vServer mit nur einem Service bietet keine Standort-Redundanz.
- **Behebung:** Zweiten Standort/Service ergänzen.
- **Quellen:** –

### HA-002 – Kein HA-Partner konfiguriert

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Einzelgerät = Single Point of Failure (sofern nicht Cluster/Cloud-HA). Annahme: Partner-Gerät ist nicht in dieser Datei beschrieben.
- **Behebung:** HA-Paar oder Cluster einrichten.
- **Quellen:** –

### QA-011 – HTTPS-vServer ohne HTTP→HTTPS-Redirect

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Nutzer, die http:// eingeben, erreichen den Dienst nicht. (Heuristik: geprüft werden `-redirectFromPort` und ein vServer auf Port 80 an derselben IP.)
- **Behebung:** `-redirectFromPort 80 -httpsRedirectUrl https://<fqdn>` oder Redirect-vServer auf Port 80.
- **Quellen:** –

### WAF-003 – HTTP(S)-vServer ohne WAF

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Übersicht: HTTP/SSL-vServer ohne AppFW-Policy. Ob eine WAF gefordert ist, hängt vom Schutzbedarf der Anwendung ab (BSI APP.3.1).
- **Behebung:** AppFW-Policy binden, wo Schutzbedarf es verlangt.
- **Quellen:** BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

## Compliance (BSI / Herstellervorgaben)

### MGMT-001 – Telnet auf einer NetScaler-IP aktiviert

- **Schweregrad:** critical · **Sicherheit der Aussage:** certain
- **Begründung:** Telnet überträgt Zugangsdaten im Klartext.
- **Behebung:** `set ns ip <ip> -telnet DISABLED`; Administration nur per SSH.
- **Quellen:** BSI IT-Grundschutz NET.1.2 Netzmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### TLS-001 – SSLv3 aktiviert

- **Schweregrad:** critical · **Sicherheit der Aussage:** certain
- **Begründung:** SSLv3 ist durch POODLE gebrochen und nach TR-02102-2 nicht zulässig.
- **Behebung:** `set ssl vserver <vs> -ssl3 DISABLED` bzw. im SSL-Profil.
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security); BSI IT-Grundschutz CON.1 Kryptokonzept

### AAA-001 – LDAP-Anbindung ohne Verschlüsselung

- **Schweregrad:** high · **Sicherheit der Aussage:** likely
- **Begründung:** `-secType PLAINTEXT` (auch der Standardwert, wenn die Option fehlt) überträgt Bind-DN und Kennwörter im Klartext.
- **Behebung:** `-secType SSL` (LDAPS/636) oder `TLS` (StartTLS) und Server-Zertifikat prüfen (`-validateServerCert YES` ab 13.1/14.1).
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security); BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; Citrix/NetScaler Secure Deployment Guide

### AAA-003 – Gateway/Auth-vServer ohne TLS

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Gateway- und Authentifizierungs-vServer müssen TLS terminieren, sonst gehen Zugangsdaten im Klartext über das Netz.
- **Behebung:** vServer-Typ SSL verwenden, Zertifikat binden.
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security); BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

### AAA-008 – SAML: unsignierte Assertions akzeptiert

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Mit `-samlRejectUnsignedAssertion OFF` werden unsignierte Assertions akzeptiert (Impersonation möglich).
- **Behebung:** `ON` (bzw. `STRICT`) setzen.
- **Quellen:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; Citrix/NetScaler Secure Deployment Guide

### MGMT-002 – GUI-Zugriff über unverschlüsseltes HTTP

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** `-gui ENABLED` erlaubt HTTP-GUI; `SECUREONLY` erzwingt HTTPS.
- **Behebung:** `set ns ip <ip> -gui SECUREONLY` (bzw. DISABLED auf Nicht-NSIPs).
- **Quellen:** BSI IT-Grundschutz NET.1.2 Netzmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### MGMT-007 – Kennwort im Klartext in der Konfiguration

- **Schweregrad:** high · **Sicherheit der Aussage:** likely
- **Begründung:** Ein `-password`-Parameter ohne `-encrypted` bzw. ein Klartext-Kennwort bei `add system user` liegt im Klartext vor.
- **Behebung:** Kennwort neu setzen und `save ns config`, sodass es verschlüsselt gespeichert wird; Klartext-Config nicht weitergeben.
- **Quellen:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; BSI IT-Grundschutz CON.1 Kryptokonzept

### MGMT-012 – SNMP-Community mit Standardname

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Standard-Communities (public/private …) sind allgemein bekannt; SNMP v1/v2c ist ungeschützt.
- **Behebung:** Community ändern/entfernen, SNMPv3 (`add snmp user`/`add snmp group`) verwenden, `add snmp manager` auf Monitoring-Server beschränken.
- **Quellen:** BSI IT-Grundschutz NET.1.2 Netzmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### TLS-002 – TLS 1.0/1.1 aktiviert

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** TLS 1.0 und 1.1 gelten als veraltet; TR-02102-2 empfiehlt TLS 1.2/1.3.
- **Behebung:** `-tls1 DISABLED -tls11 DISABLED` am vServer bzw. SSL-Profil.
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security)

### TLS-003 – Schwache Cipher gebunden

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** RC4, (3)DES, EXPORT, NULL, MD5 und anonyme Suiten sind nach TR-02102-2 nicht zulässig; die Gruppe ALL enthält solche Suiten.
- **Behebung:** Eigene Cipher-Gruppe mit ECDHE-AEAD-Suiten (TLS1.3 + TLS1.2 GCM) binden, `unbind ssl vserver <vs> -cipherName DEFAULT/ALL`.
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security); Citrix/NetScaler Secure Deployment Guide (TLS)

### AAA-002 – LDAPS/TLS ohne Zertifikatsprüfung

- **Schweregrad:** medium · **Sicherheit der Aussage:** heuristic
- **Begründung:** Bei `-validateServerCert NO` bzw. fehlender Angabe wird das LDAP-Serverzertifikat nicht geprüft (Standardwert versionsabhängig — daher heuristisch).
- **Behebung:** `-validateServerCert YES` und CA am Gerät hinterlegen.
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security); Citrix/NetScaler Secure Deployment Guide

### CHAIN-002 – Double-Hop: Verbindung zwischen den NetScalern unverschlüsselt

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Der Frontend-NetScaler spricht den Backend-NetScaler per HTTP/TCP an, obwohl dazwischen ggf. ein schützenswertes Netz liegt (z.B. DMZ → intern).
- **Behebung:** Service-Typ SSL mit Server-Zertifikatsprüfung verwenden (Backend-Profil).
- **Quellen:** BSI TR-02102-2; BSI IT-Grundschutz NET.1.1 Network architecture and design

### MGMT-004 – FTP auf einer NetScaler-IP aktiviert

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** FTP ist unverschlüsselt.
- **Behebung:** `set ns ip <ip> -ftp DISABLED`; SFTP/SCP verwenden.
- **Quellen:** BSI IT-Grundschutz NET.1.2 Netzmanagement

### MGMT-005 – Starke Kennwortrichtlinie nicht aktiviert

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Ohne `-strongpassword ENABLED` und ausreichende Mindestlänge sind schwache Admin-Kennwörter möglich.
- **Behebung:** `set system parameter -strongpassword ENABLED -minpasswordlen 14`.
- **Quellen:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### MGMT-008 – nsroot-Kennwort vermutlich nie geändert

- **Schweregrad:** medium · **Sicherheit der Aussage:** heuristic
- **Begründung:** Eine Konfiguration ohne `set system user nsroot ... -encrypted` deutet auf das Default-Kennwort hin (Annahme; Hashes lassen sich nicht auf 'nsroot' prüfen, weil sie gesalzen sind).
- **Behebung:** Kennwort des nsroot ändern, besser: eigene Admin-Konten + nsroot einschränken.
- **Quellen:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### MGMT-010 – Keine Remote-Protokollierung (Syslog/NSLOG)

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** Ohne Syslog-/NSLOG-Ziel gehen Audit-Informationen bei Gerätewechsel/Kompromittierung verloren.
- **Behebung:** `add audit syslogAction ...`, `add audit syslogPolicy ...` und `bind audit syslogGlobal -policyName ...`.
- **Quellen:** BSI IT-Grundschutz OPS.1.1.5 Protokollierung; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### TLS-010 – Backend-TLS ohne Zertifikatsprüfung

- **Schweregrad:** medium · **Sicherheit der Aussage:** heuristic
- **Begründung:** SSL-Services ohne `-serverAuth ENABLED` (bzw. Backend-Profil mit serverAuth) prüfen das Server-Zertifikat nicht; Man-in-the-Middle im Backend-Netz bleibt unentdeckt. Das Ergebnis ist heuristisch, weil Profile/Standards je Version variieren.
- **Behebung:** SSL-Backend-Profil mit `-serverAuth ENABLED` und CA-Zertifikat am Service(Group) binden.
- **Quellen:** BSI TR-02102-2 (Verwendung von Transport Layer Security); BSI IT-Grundschutz NET.1.1 Netzarchitektur und -design (Absicherung interner Verbindungen)

