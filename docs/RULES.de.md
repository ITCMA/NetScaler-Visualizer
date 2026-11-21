# Prüfregeln

Automatisch erzeugt mit `python -m nsviz rules --markdown --lang de`. Jede Regel hat Schweregrad, Kategorie und eine **Sicherheit der Aussage** (`certain` = eindeutig aus der Config ableitbar, `likely` = übliche Annahme, `heuristic` = Näherung, bitte im Einzelfall prüfen).

> Die Verweise auf BSI-Bausteine und die Secure-Deployment-Hinweise des Herstellers nennen den Baustein bzw. das Thema, **nicht** einzelne Anforderungs-IDs. Das Mapping ist als fachliche Einordnung gedacht und sollte vor Verwendung in einem Audit gegen die jeweils aktuelle Fassung geprüft werden.

## Fehlkonfiguration

### AAA-004 – Gateway ohne Authentifizierung

- **Schweregrad:** high · **Sicherheit der Aussage:** likely
- **Begründung:** `-authentication OFF` erlaubt anonymen Zugriff; ein Gateway ohne gebundene Auth-Policy/Authn-Profil bietet ebenfalls keine Anmeldung (Annahme: Auth ist nicht über Standard-Authentifizierung/andere Wege geregelt).
- **Behebung:** Auth-Policy binden (`bind vpn vserver <gw> -policy <authpol> -priority 100`) oder `-authnProfile` setzen.
- **Quellen:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement

### CLU-002 – Cluster und HA gleichzeitig konfiguriert

- **Schweregrad:** high · **Sicherheit der Aussage:** likely
- **Begründung:** Cluster und klassisches HA-Paar schließen sich auf einer Appliance aus. Die Konfiguration enthält sowohl `add cluster instance` als auch `add ha node`.
- **Behebung:** Sich für ein Modell entscheiden und die Konfiguration des anderen entfernen.
- **Quellen:** –

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

### RW-001 – Policy in falscher Richtung gebunden

- **Schweregrad:** high · **Sicherheit der Aussage:** certain
- **Begründung:** Ausdruck oder Action der Policy bezieht sich auf die jeweils andere Seite der HTTP-Transaktion (Anfrage bzw. Antwort), die am Bindepunkt nicht verfügbar oder nicht relevant ist. Die Policy greift nie oder wirkungslos.
- **Behebung:** Die Policy am passenden Bindepunkt (REQUEST oder RESPONSE) binden oder den Ausdruck korrigieren.
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

### CLU-001 – Cluster-Knoten ohne Backplane

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Cluster-Knoten tauschen Verkehr und Status über die Backplane aus. Ein Knoten ohne `-backplane` kann nicht am Cluster teilnehmen. Wahrscheinlich: bei Teilexporten kann die Option fehlen.
- **Behebung:** Das Backplane-Interface des Knotens setzen.
- **Quellen:** –

### DEP-001 – vServer nicht erreichbar

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Dieser vServer ist nicht adressierbar (keine IP/Port) und kein anderer vServer, keine Policy und keine globale Bindung führt zu ihm. Kein Verkehr erreicht ihn; oft ein Überbleibsel.
- **Behebung:** Als Ziel eines CS-/LB-vServers oder einer Policy binden, eine Adresse vergeben oder entfernen.
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

### LB-003 – Backup-vServer bilden eine Schleife

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** Die Backup-vServer verweisen im Kreis aufeinander. Fällt der primäre vServer aus, erreicht der Verkehr keinen vServer, der ihn bedienen kann.
- **Behebung:** Die Schleife auflösen, sodass die Kette der Backup-vServer an einem vServer ohne `-backupVServer` endet.
- **Quellen:** –

### MGMT-015 – SNMP-Community ohne Einschränkung auf Manager

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Es gibt SNMP-Communities, aber keinen konfigurierten SNMP-Manager. Ohne Manager-Liste beantwortet der Agent Abfragen jedes Hosts, der den Community-String kennt.
- **Behebung:** Die Überwachungssysteme mit `add snmp manager` eintragen, damit nur diese akzeptiert werden.
- **Quellen:** BSI IT-Grundschutz NET.1.2 Netzmanagement

### NET-001 – Gateway einer Route nicht in einem direkt verbundenen Netz

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Das Gateway der Route liegt in keinem Subnetz von NSIP oder SNIP; die Appliance hat keinen direkten Weg dorthin. Wahrscheinlich: Routen anderer Traffic Domains und dynamisches Routing werden nicht ausgewertet.
- **Behebung:** Gateway-Adresse korrigieren oder die SNIP des fehlenden Subnetzes ergänzen.
- **Quellen:** BSI IT-Grundschutz NET.1.1 Netzarchitektur und -design

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

### VPN-002 – ICA-Proxy ohne STA-Server

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Eine Session-Action aktiviert ICA-Proxy, am Gateway-vServer ist aber keine Secure Ticket Authority gebunden; ICA-Sitzungen kommen nicht zustande. Wahrscheinlich: eine STA kann an einem vServer außerhalb dieser Datei konfiguriert sein.
- **Behebung:** Mindestens einen STA-Server an den Gateway-vServer binden.
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

### NET-003 – Traffic Domain ohne VLAN

- **Schweregrad:** low · **Sicherheit der Aussage:** likely
- **Begründung:** Eine Traffic Domain benötigt mindestens ein gebundenes VLAN, um Verkehr zu trennen; ohne VLAN hat sie keine Netzanbindung.
- **Behebung:** Ein VLAN an die Traffic Domain binden oder sie entfernen.
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

### CS-001 – Content-Switching-vServer ohne Policy

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Der vServer hat Bindungen, aber keine Content-Switching-Policy; jede Anfrage geht an das Standardziel. Ein einfacher Load-Balancing-vServer leistet dasselbe mit weniger Konfiguration. Heuristik.
- **Behebung:** Prüfen, ob der Content-Switching-vServer noch benötigt wird, oder die vorgesehenen Policies binden.
- **Quellen:** –

### DEP-002 – URL-Ziel keinem vServer zugeordnet

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Eine Gateway-Session-Action oder ein STA-Server zeigt auf einen Host, der keinem vServer dieses Geräts nach IP und Port entspricht (FQDN, anderes Gerät oder externer Dienst). Die Verbindung lässt sich allein aus der Config nicht ableiten (Annahme: IP und Port werden verglichen).
- **Behebung:** Ziel prüfen. Bei FQDN die Zuordnung (Tab Verknüpfung) oder eine Hosts-Datei nutzen, um den richtigen vServer zu verbinden.
- **Quellen:** –

### NET-002 – VLAN ohne Interface-Bindung

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Ein VLAN ohne gebundenes Interface oder gebundenen Channel überträgt keinen Verkehr. Heuristik: auch VLANs, an die nur IP-Adressen gebunden sind, werden gemeldet.
- **Behebung:** Interface oder Channel binden oder das VLAN entfernen.
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

### QA-013 – Mehrere Zertifikatsobjekte nutzen dieselbe Datei

- **Schweregrad:** info · **Sicherheit der Aussage:** certain
- **Begründung:** Mehrere Objekte verweisen auf dieselbe Zertifikatsdatei. Doppelte Objekte erschweren die Erneuerung, weil jede Kopie angepasst werden muss.
- **Behebung:** Ein Zertifikatsobjekt verwenden und überall dort binden, wo es gebraucht wird.
- **Quellen:** –

### QA-014 – Deaktivierter Server wird noch verwendet

- **Schweregrad:** info · **Sicherheit der Aussage:** certain
- **Begründung:** Der Server steht auf DISABLED, wird aber noch von Services oder Service Groups verwendet. Er erhält keinen Verkehr; das kann eine Wartung sein, ist aber oft ein Überbleibsel.
- **Behebung:** Verweise und Server entfernen oder den Server wieder aktivieren.
- **Quellen:** –

### QA-015 – Mehrere Serverobjekte mit derselben Adresse

- **Schweregrad:** info · **Sicherheit der Aussage:** certain
- **Begründung:** Mehrere Serverobjekte zeigen auf dieselbe Adresse. Doppelte Objekte machen unklar, zu welchem Objekt eine Änderung gehört.
- **Behebung:** Pro Adresse ein Serverobjekt verwenden.
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

### LB-001 – Health-Monitoring am Service abgeschaltet

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** Mit `-healthMonitor NO` gilt der Service immer als verfügbar, auch wenn der Server ausgefallen ist; die Appliance sendet weiter Verkehr dorthin.
- **Behebung:** `-healthMonitor NO` entfernen und einen zur Anwendung passenden Monitor binden.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide

### MODE-001 – Layer-2-Modus aktiv

- **Schweregrad:** medium · **Sicherheit der Aussage:** likely
- **Begründung:** Mit L2-Modus leitet die Appliance Pakete weiter, die nicht an sie adressiert sind. In Netzen mit mehreren Pfaden kann das Bridging-Schleifen erzeugen. Nur aktivieren, wenn der Einsatz es erfordert.
- **Behebung:** Den Modus mit `disable ns mode L2` abschalten, falls der Einsatz ihn nicht benötigt.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide

### TLS-006 – SSL-Neuverhandlung nicht eingeschränkt

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** `-denySSLReneg NO` erlaubt Client-initiierte Renegotiation (DoS-Vektor).
- **Behebung:** `-denySSLReneg FRONTEND_CLIENT` (Standard) oder `ALL`.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide (TLS)

### VPN-001 – Standard-Autorisierung ist ALLOW

- **Schweregrad:** medium · **Sicherheit der Aussage:** certain
- **Begründung:** Mit `-defaultAuthorizationAction ALLOW` erreichen authentifizierte Benutzer jede Ressource, die keine Autorisierungs-Policy verbietet. Empfohlen ist DENY mit expliziten Erlauben-Policies.
- **Behebung:** Den Standard auf DENY setzen und Zugriffe über Autorisierungs-Policies erlauben.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide

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

### MGMT-016 – Nur ein NTP-Server

- **Schweregrad:** low · **Sicherheit der Aussage:** heuristic
- **Begründung:** Eine einzelne Zeitquelle ist ein Single Point of Failure für die Zeitsynchronisation; das betrifft Logs, Zertifikate und HA.
- **Behebung:** Mindestens zwei NTP-Server konfigurieren.
- **Quellen:** BSI IT-Grundschutz OPS.1.1.5 Protokollierung

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

### VPN-003 – Keine Begrenzung fehlgeschlagener Anmeldungen

- **Schweregrad:** low · **Sicherheit der Aussage:** likely
- **Begründung:** Ohne `-maxLoginAttempts` sind fehlgeschlagene Anmeldungen nicht begrenzt; das erlaubt das Erraten von Kennwörtern am Gateway oder Authentifizierungs-vServer. Wahrscheinlich: eine Begrenzung kann anderweitig gesetzt sein.
- **Behebung:** `-maxLoginAttempts` zusammen mit `-failedLoginTimeout` setzen.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide

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

### LB-002 – HTTP(S)-Service nur mit Standard-Monitor überwacht

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Ohne gebundenen Monitor läuft nur die Standard-TCP-Prüfung. Sie bestätigt einen offenen Port, nicht eine korrekte Antwort der Anwendung. Heuristik: Monitore, die nicht in dieser Datei stehen, sind nicht sichtbar.
- **Behebung:** Einen HTTP-, HTTP-ECV- oder anwendungsspezifischen Monitor binden, der eine sinnvolle Antwort prüft.
- **Quellen:** –

### MGMT-017 – Nur ein DNS-Nameserver

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Mit nur einem Nameserver fällt die Namensauflösung aus, wenn dieser nicht erreichbar ist.
- **Behebung:** Mindestens zwei Nameserver konfigurieren.
- **Quellen:** –

### QA-011 – HTTPS-vServer ohne HTTP→HTTPS-Redirect

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Nutzer, die http:// eingeben, erreichen den Dienst nicht. (Heuristik: geprüft werden `-redirectFromPort` und ein vServer auf Port 80 an derselben IP.)
- **Behebung:** `-redirectFromPort 80 -httpsRedirectUrl https://<fqdn>` oder Redirect-vServer auf Port 80.
- **Quellen:** –

### TLS-012 – TLS-Einstellungen am vServer statt in einem SSL-Profil

- **Schweregrad:** info · **Sicherheit der Aussage:** likely
- **Begründung:** Protokolloptionen, die direkt am vServer gesetzt sind, lassen sich über viele vServer schwerer einheitlich halten als ein gemeinsames SSL-Profil. Einstellungen im Profil werden an einer Stelle geprüft und geändert.
- **Behebung:** Die Einstellungen in ein SSL-Profil übernehmen und das Profil binden.
- **Quellen:** Citrix/NetScaler Secure Deployment Guide

### WAF-003 – HTTP(S)-vServer ohne WAF

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Übersicht: HTTP/SSL-vServer ohne AppFW-Policy. Ob eine WAF gefordert ist, hängt vom Schutzbedarf der Anwendung ab (BSI APP.3.1).
- **Behebung:** AppFW-Policy binden, wo Schutzbedarf es verlangt.
- **Quellen:** BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

### WAF-004 – WAF-Profil ohne Signaturobjekt

- **Schweregrad:** info · **Sicherheit der Aussage:** heuristic
- **Begründung:** Das Profil hat kein Signaturobjekt; der signaturbasierte Schutz vor bekannten Angriffsmustern wird nicht genutzt. Heuristik: Signaturen können auch auf nicht in der Datei sichtbare Weise zugeordnet sein.
- **Behebung:** Ein Signaturobjekt anlegen oder auswählen und dem Profil zuordnen.
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

