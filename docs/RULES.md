# Check rules

Generated with `python -m nsviz rules --markdown`. Every rule has a severity, a category and a **confidence** (`certain` = derivable from the config alone, `likely` = common assumption, `heuristic` = approximation, please verify case by case).

> References to BSI modules and the vendor secure deployment guidance name the module or topic, **not** individual requirement IDs. The mapping is a technical classification and must be checked against the current edition before use in an audit.

## Misconfiguration

### AAA-004 – Gateway without authentication

- **Severity:** high · **Confidence:** likely
- **Rationale:** `-authentication OFF` allows anonymous access; a gateway without a bound auth policy or authn profile offers no login either (assumption: authentication is not handled by other means).
- **Remediation:** Bind an auth policy (`bind vpn vserver <gw> -policy <authpol> -priority 100`) or set `-authnProfile`.
- **Sources:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement

### HA-003 – Configuration drift between HA nodes

- **Severity:** high · **Confidence:** likely
- **Rationale:** After synchronization both nodes should be identical (except node-specific objects such as NSIP, hostname, interfaces). Drift leads to different behavior after failover.
- **Remediation:** Check sync (`show ha node`, `force ha sync`), clarify causes (manual change with -haProp DISABLED, sync errors).
- **Sources:** Citrix/NetScaler documentation: high availability (synchronization)

### QA-007 – Reference to non-existent object

- **Severity:** high · **Confidence:** likely
- **Rationale:** A binding/option refers to an object that does not exist in the configuration (typo, incomplete export or deleted object). With partial exports this is expected — assumption: the config is complete.
- **Remediation:** Create the object or correct the reference.
- **Sources:** –

### QA-008 – Duplicate vServer address (IP:port)

- **Severity:** high · **Confidence:** certain
- **Rationale:** Two vServers with the same IP/port/protocol collide.
- **Remediation:** Change one address.
- **Sources:** –

### QA-009 – Objects configured but feature not enabled

- **Severity:** high · **Confidence:** certain
- **Rationale:** Without `enable ns feature <X>` the objects of that function are ineffective (and sometimes cannot be created).
- **Remediation:** `enable ns feature <feature>`.
- **Sources:** –

### QA-010 – CS vServer without target

- **Severity:** high · **Confidence:** certain
- **Rationale:** A CS vServer without a default LB vServer and without policies does nothing useful.
- **Remediation:** Bind a default LB vServer (`bind cs vserver <cs> <lb>`) and/or CS policies.
- **Sources:** –

### TLS-004 – TLS 1.2 disabled

- **Severity:** high · **Confidence:** certain
- **Rationale:** Without TLS 1.2 only obsolete protocols remain (or TLS 1.3 only).
- **Remediation:** `-tls12 ENABLED`.
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security)

### TLS-008 – SSL vServer without certificate

- **Severity:** high · **Confidence:** certain
- **Rationale:** A TLS-terminating vServer without a bound certificate is DOWN or cannot complete handshakes.
- **Remediation:** `bind ssl vserver <vs> -certkeyName <cert>`.
- **Sources:** –

### AAA-005 – nFactor: policy label without login schema

- **Severity:** medium · **Confidence:** likely
- **Rationale:** A policy label without `-loginSchema` shows no input fields; it only makes sense with `LSCHEMA_INT` (no UI).
- **Remediation:** `add authentication policylabel <name> -loginSchema <schema>`, or deliberately `LSCHEMA_INT` for pass-through factors.
- **Sources:** –

### AAA-007 – Authentication vServer without policy

- **Severity:** medium · **Confidence:** certain
- **Rationale:** An authentication vServer without a bound policy cannot authenticate anyone.
- **Remediation:** Bind auth policies with priorities.
- **Sources:** –

### DEP-001 – vServer not reachable

- **Severity:** medium · **Confidence:** likely
- **Rationale:** This vServer is not addressable (no IP/port) and no other vServer, policy or global binding leads to it, so no traffic can reach it. Often a leftover.
- **Remediation:** Bind it as a target of a CS/LB vServer or policy, give it an address, or remove it.
- **Sources:** –

### GSLB-001 – GSLB vServer without domain

- **Severity:** medium · **Confidence:** certain
- **Rationale:** Without `bind gslb vserver -domainName` the vServer answers no DNS queries.
- **Remediation:** Bind a domain.
- **Sources:** –

### GSLB-002 – GSLB without ADNS service

- **Severity:** medium · **Confidence:** likely
- **Rationale:** GSLB answers require an ADNS service (or DNS proxy operation). Assumption: ADNS is not operated on another appliance.
- **Remediation:** `add service <name> <ip> ADNS 53`.
- **Sources:** –

### HA-001 – HA synchronization/propagation disabled

- **Severity:** medium · **Confidence:** certain
- **Rationale:** `-haSync DISABLED` or `-haProp DISABLED` leads to configuration drift between the nodes.
- **Remediation:** `set ha node -haSync ENABLED -haProp ENABLED`.
- **Sources:** –

### QA-001 – LB vServer without bound service

- **Severity:** medium · **Confidence:** certain
- **Rationale:** An LB vServer without a service/service group has no backend and is DOWN.
- **Remediation:** Bind a service/service group or remove the vServer.
- **Sources:** –

### REP-001 – IP reputation rules but feature/settings missing

- **Severity:** medium · **Confidence:** heuristic
- **Rationale:** Policies with `IPREP` expressions are only evaluated if the reputation feature is enabled (assumption: feature name `REP`, may be named differently in 13.1+) and the appliance can fetch reputation data (`set reputation settings`).
- **Remediation:** Check `enable ns feature REP` and `set reputation settings -proxyServer …` (if a proxy is needed).
- **Sources:** –

### WAF-001 – WAF profile without policy binding

- **Severity:** medium · **Confidence:** certain
- **Rationale:** An AppFW profile without a policy protects nothing.
- **Remediation:** Create `add appfw policy` and bind it to a vServer or globally.
- **Sources:** BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

### AAA-006 – nFactor: policy label unreachable

- **Severity:** low · **Confidence:** certain
- **Rationale:** A policy label that is not reached through any `-nextFactor` is dead configuration.
- **Remediation:** Remove it or link it.
- **Sources:** –

### QA-002 – Service/service group not bound to any vServer

- **Severity:** low · **Confidence:** certain
- **Rationale:** Unbound services cause monitoring load and confusion without benefit.
- **Remediation:** Bind or remove.
- **Sources:** –

### QA-004 – Policy without binding

- **Severity:** low · **Confidence:** certain
- **Rationale:** A policy that is bound nowhere has no effect.
- **Remediation:** Bind or remove.
- **Sources:** –

### QA-005 – Unused certificate

- **Severity:** low · **Confidence:** certain
- **Rationale:** Unused certificates increase the attack surface and obscure expiry monitoring.
- **Remediation:** Remove.
- **Sources:** –

### DEP-002 – URL target not matched to a vServer

- **Severity:** info · **Confidence:** heuristic
- **Rationale:** A Gateway session action or STA server points to a host that does not match a vServer of this device by IP and port (FQDN, another device or an external service). The connection cannot be derived from the config alone (assumption: IP and port are compared).
- **Remediation:** Check the target. For FQDNs use the link map or a hosts file (Links tab) to connect it to the right vServer.
- **Sources:** –

### QA-003 – Unused server object

- **Severity:** info · **Confidence:** certain
- **Rationale:** `add server` without any service/service group.
- **Remediation:** Remove if no longer needed.
- **Sources:** –

### QA-006 – Monitor without binding

- **Severity:** info · **Confidence:** certain
- **Rationale:** Unbound monitor.
- **Remediation:** Remove or bind.
- **Sources:** –

### QA-012 – vServer administratively disabled

- **Severity:** info · **Confidence:** certain
- **Rationale:** Disabled vServers often remain in configs as legacy.
- **Remediation:** Remove if permanently unneeded.
- **Sources:** –

## Best practice

### MGMT-003 – Management access enabled on SNIP/VIP

- **Severity:** high · **Confidence:** certain
- **Rationale:** Management services (SSH/GUI/SNMP) should only be reachable via the NSIP or a management network, not via data-plane addresses.
- **Remediation:** `set ns ip <snip> -mgmtAccess DISABLED -telnet DISABLED -ssh DISABLED -gui DISABLED -snmp DISABLED`; allow management access on the NSIP only, with ACLs where appropriate.
- **Sources:** Citrix/NetScaler Secure Deployment Guide (section management access/hardening); BSI IT-Grundschutz NET.1.2 Netzmanagement

### TLS-007 – Self-signed default certificate on vServer

- **Severity:** high · **Confidence:** certain
- **Rationale:** `ns-server-certificate` is self-signed and device-specific; clients cannot validate it.
- **Remediation:** Bind a certificate from a trusted CA.
- **Sources:** Citrix/NetScaler Secure Deployment Guide (TLS); BSI IT-Grundschutz CON.1 Kryptokonzept

### TLS-006 – SSL renegotiation not restricted

- **Severity:** medium · **Confidence:** certain
- **Rationale:** `-denySSLReneg NO` allows client-initiated renegotiation (DoS vector).
- **Remediation:** `-denySSLReneg FRONTEND_CLIENT` (default) or `ALL`.
- **Sources:** Citrix/NetScaler Secure Deployment Guide (TLS)

### GSLB-004 – GSLB metric exchange (MEP) disabled

- **Severity:** low · **Confidence:** certain
- **Rationale:** With several sites, no load or status information is exchanged between sites without MEP.
- **Remediation:** Set `-metricExchange ENABLED`.
- **Sources:** –

### MGMT-006 – Password change at first login not enforced

- **Severity:** low · **Confidence:** likely
- **Rationale:** `-forcePasswordChange` forces changing the default password.
- **Remediation:** `set system parameter -forcePasswordChange ENABLED`.
- **Sources:** Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### MGMT-009 – No external authentication for administrators

- **Severity:** low · **Confidence:** likely
- **Rationale:** Without `bind system global <auth-policy>` admins are managed locally only (no central access management or traceability).
- **Remediation:** Create an LDAP/RADIUS/TACACS+ policy for management authentication and bind it with `bind system global`.
- **Sources:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement

### MGMT-011 – No time synchronization (NTP)

- **Severity:** low · **Confidence:** likely
- **Rationale:** Without NTP, logs and certificate validation are unreliable.
- **Remediation:** `add ntp server <ip>` and `enable ntp sync`.
- **Sources:** BSI IT-Grundschutz OPS.1.1.5 Protokollierung

### MGMT-013 – SNMP v1/v2c used instead of SNMPv3

- **Severity:** low · **Confidence:** likely
- **Rationale:** Community-based SNMP offers neither encryption nor strong authentication.
- **Remediation:** Configure SNMPv3 with authPriv.
- **Sources:** BSI IT-Grundschutz NET.1.2 Netzmanagement

### MGMT-014 – HTTP hardening parameters not set

- **Severity:** low · **Confidence:** heuristic
- **Rationale:** The Secure Deployment Guide recommends, among others, `set ns httpParam -dropInvalReqs ON` (drop invalid HTTP requests). Please verify the exact recommendation against the current version of the guide.
- **Remediation:** `set ns httpParam -dropInvalReqs ON -markHttp09Inval ON -markConnReqInval ON`.
- **Sources:** Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### TLS-005 – TLS 1.3 not enabled

- **Severity:** low · **Confidence:** likely
- **Rationale:** TLS 1.3 is supported since NetScaler 12.1 and recommended by TR-02102-2. Only explicitly disabled TLS 1.3 is reported; missing values (defaults depend on version/profile) are an assumption.
- **Remediation:** `-tls13 ENABLED`.
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security)

### TLS-009 – Certificate expiry monitoring disabled

- **Severity:** low · **Confidence:** certain
- **Rationale:** With `-expiryMonitor DISABLED` there is no warning before expiry. The actual expiry date is not in the ns.conf and cannot be checked here.
- **Remediation:** `set ssl certKey <ck> -expiryMonitor ENABLED -notificationPeriod 30`.
- **Sources:** Citrix/NetScaler Secure Deployment Guide (TLS)

### TLS-011 – No HSTS configured

- **Severity:** low · **Confidence:** heuristic
- **Rationale:** Without an HTTP Strict Transport Security header, browsers can fall back to HTTP.
- **Remediation:** Rewrite policy with `Strict-Transport-Security`, or `-HSTS ENABLED` in the SSL profile.
- **Sources:** BSI IT-Grundschutz APP.3.2 Webserver / APP.3.1 Webanwendungen und Webservices

### WAF-002 – WAF profile without blocking action

- **Severity:** low · **Confidence:** heuristic
- **Rationale:** Without `block` in any check action the profile effectively runs in observation mode only. Heuristic: all `...Action` options of the profile are checked; defaults from `-defaults basic/advanced` are not resolved.
- **Remediation:** Validate the checks in learning mode, then set `block log stats`.
- **Sources:** BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

### CHAIN-001 – Double hop: match by IP only

- **Severity:** info · **Confidence:** heuristic
- **Rationale:** The backend target matches a frontend address of the downstream NetScaler only in the IP, not in the port (e.g. port mapping/NAT in between). The match is an assumption.
- **Remediation:** Verify the mapping manually.
- **Sources:** –

### GSLB-003 – GSLB vServer with fewer than two services

- **Severity:** info · **Confidence:** certain
- **Rationale:** A GSLB vServer with a single service offers no site redundancy.
- **Remediation:** Add a second site/service.
- **Sources:** –

### HA-002 – No HA partner configured

- **Severity:** info · **Confidence:** heuristic
- **Rationale:** A single appliance is a single point of failure (unless cluster/cloud HA is used). Assumption: the partner is not described in this file.
- **Remediation:** Set up an HA pair or cluster.
- **Sources:** –

### QA-011 – HTTPS vServer without HTTP→HTTPS redirect

- **Severity:** info · **Confidence:** heuristic
- **Rationale:** Users who type http:// cannot reach the service. (Heuristic: `-redirectFromPort` and a vServer on port 80 on the same IP are checked.)
- **Remediation:** `-redirectFromPort 80 -httpsRedirectUrl https://<fqdn>` or a redirect vServer on port 80.
- **Sources:** –

### WAF-003 – HTTP(S) vServer without WAF

- **Severity:** info · **Confidence:** heuristic
- **Rationale:** Overview of HTTP/SSL vServers without an AppFW policy. Whether a WAF is required depends on the protection needs of the application (BSI APP.3.1).
- **Remediation:** Bind an AppFW policy where the protection needs require it.
- **Sources:** BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

## Compliance (BSI / vendor guidance)

### MGMT-001 – Telnet enabled on a NetScaler IP

- **Severity:** critical · **Confidence:** certain
- **Rationale:** Telnet transmits credentials in clear text.
- **Remediation:** `set ns ip <ip> -telnet DISABLED`; administer via SSH only.
- **Sources:** BSI IT-Grundschutz NET.1.2 Netzmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### TLS-001 – SSLv3 enabled

- **Severity:** critical · **Confidence:** certain
- **Rationale:** SSLv3 is broken by POODLE and not permitted by TR-02102-2.
- **Remediation:** `set ssl vserver <vs> -ssl3 DISABLED` or in the SSL profile.
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security); BSI IT-Grundschutz CON.1 Kryptokonzept

### AAA-001 – LDAP connection without encryption

- **Severity:** high · **Confidence:** likely
- **Rationale:** `-secType PLAINTEXT` (also the default when the option is missing) sends the bind DN and passwords in clear text.
- **Remediation:** Use `-secType SSL` (LDAPS/636) or `TLS` (StartTLS) and verify the server certificate (`-validateServerCert YES` from 13.1/14.1).
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security); BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; Citrix/NetScaler Secure Deployment Guide

### AAA-003 – Gateway/auth vServer without TLS

- **Severity:** high · **Confidence:** certain
- **Rationale:** Gateway and authentication vServers must terminate TLS, otherwise credentials cross the network in clear text.
- **Remediation:** Use vServer type SSL and bind a certificate.
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security); BSI IT-Grundschutz APP.3.1 Webanwendungen und Webservices

### AAA-008 – SAML: unsigned assertions accepted

- **Severity:** high · **Confidence:** certain
- **Rationale:** With `-samlRejectUnsignedAssertion OFF`, unsigned assertions are accepted (impersonation possible).
- **Remediation:** Set `ON` (or `STRICT`).
- **Sources:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; Citrix/NetScaler Secure Deployment Guide

### MGMT-002 – GUI access over unencrypted HTTP

- **Severity:** high · **Confidence:** certain
- **Rationale:** `-gui ENABLED` allows the HTTP GUI; `SECUREONLY` enforces HTTPS.
- **Remediation:** `set ns ip <ip> -gui SECUREONLY` (or DISABLED on non-NSIPs).
- **Sources:** BSI IT-Grundschutz NET.1.2 Netzmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### MGMT-007 – Password in clear text in the configuration

- **Severity:** high · **Confidence:** likely
- **Rationale:** A `-password` parameter without `-encrypted`, or a clear-text password in `add system user`, is stored in clear text.
- **Remediation:** Set the password again and `save ns config` so it is stored encrypted; do not hand out clear-text configs.
- **Sources:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; BSI IT-Grundschutz CON.1 Kryptokonzept

### MGMT-012 – SNMP community with default name

- **Severity:** high · **Confidence:** certain
- **Rationale:** Default communities (public/private …) are well known; SNMP v1/v2c is unprotected.
- **Remediation:** Change/remove the community, use SNMPv3 (`add snmp user`/`add snmp group`), restrict `add snmp manager` to the monitoring server.
- **Sources:** BSI IT-Grundschutz NET.1.2 Netzmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### TLS-002 – TLS 1.0/1.1 enabled

- **Severity:** high · **Confidence:** certain
- **Rationale:** TLS 1.0 and 1.1 are considered obsolete; TR-02102-2 recommends TLS 1.2/1.3.
- **Remediation:** `-tls1 DISABLED -tls11 DISABLED` on the vServer or SSL profile.
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security)

### TLS-003 – Weak ciphers bound

- **Severity:** high · **Confidence:** certain
- **Rationale:** RC4, (3)DES, EXPORT, NULL, MD5 and anonymous suites are not permitted by TR-02102-2; the group ALL contains such suites.
- **Remediation:** Bind your own cipher group with ECDHE AEAD suites (TLS 1.3 + TLS 1.2 GCM); `unbind ssl vserver <vs> -cipherName DEFAULT/ALL`.
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security); Citrix/NetScaler Secure Deployment Guide (TLS)

### AAA-002 – LDAPS/TLS without certificate validation

- **Severity:** medium · **Confidence:** heuristic
- **Rationale:** With `-validateServerCert NO` or no value, the LDAP server certificate is not validated (default depends on the version, hence heuristic).
- **Remediation:** Set `-validateServerCert YES` and install the CA on the appliance.
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security); Citrix/NetScaler Secure Deployment Guide

### CHAIN-002 – Double hop: connection between the NetScalers unencrypted

- **Severity:** medium · **Confidence:** likely
- **Rationale:** The frontend NetScaler talks to the backend NetScaler via HTTP/TCP although a network worth protecting may lie in between (e.g. DMZ → internal).
- **Remediation:** Use service type SSL with server certificate validation (backend profile).
- **Sources:** BSI TR-02102-2; BSI IT-Grundschutz NET.1.1 Network architecture and design

### MGMT-004 – FTP enabled on a NetScaler IP

- **Severity:** medium · **Confidence:** certain
- **Rationale:** FTP is unencrypted.
- **Remediation:** `set ns ip <ip> -ftp DISABLED`; use SFTP/SCP.
- **Sources:** BSI IT-Grundschutz NET.1.2 Netzmanagement

### MGMT-005 – Strong password policy not enabled

- **Severity:** medium · **Confidence:** likely
- **Rationale:** Without `-strongpassword ENABLED` and a sufficient minimum length, weak admin passwords are possible.
- **Remediation:** `set system parameter -strongpassword ENABLED -minpasswordlen 14`.
- **Sources:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### MGMT-008 – nsroot password probably never changed

- **Severity:** medium · **Confidence:** heuristic
- **Rationale:** A configuration without `set system user nsroot ... -encrypted` suggests the default password (assumption; hashes cannot be checked against 'nsroot' because they are salted).
- **Remediation:** Change the nsroot password; better: personal admin accounts and restrict nsroot.
- **Sources:** BSI IT-Grundschutz ORP.4 Identitäts- und Berechtigungsmanagement; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### MGMT-010 – No remote logging (syslog/NSLOG)

- **Severity:** medium · **Confidence:** certain
- **Rationale:** Without a syslog/NSLOG target, audit information is lost on appliance replacement or compromise.
- **Remediation:** `add audit syslogAction ...`, `add audit syslogPolicy ...` and `bind audit syslogGlobal -policyName ...`.
- **Sources:** BSI IT-Grundschutz OPS.1.1.5 Protokollierung; Citrix/NetScaler Secure Deployment Guide (section management access/hardening)

### TLS-010 – Backend TLS without certificate validation

- **Severity:** medium · **Confidence:** heuristic
- **Rationale:** SSL services without `-serverAuth ENABLED` (or a backend profile with serverAuth) do not validate the server certificate; man-in-the-middle in the backend network goes unnoticed. The result is heuristic because profiles/defaults vary by version.
- **Remediation:** Bind an SSL backend profile with `-serverAuth ENABLED` and a CA certificate to the service (group).
- **Sources:** BSI TR-02102-2 (Verwendung von Transport Layer Security); BSI IT-Grundschutz NET.1.1 Netzarchitektur und -design (Absicherung interner Verbindungen)

