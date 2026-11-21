# Legal notes

🇩🇪 [Deutsche Version](LEGAL.de.md)

These notes describe how the project handles trademarks, third-party components, standards references and customer data.
They are information for users and are not legal advice.

## Trademarks
NetScaler and Citrix are trademarks of their respective owners. This project is an independent tool. It is not affiliated
with, endorsed or supported by the trademark owners; the names are used only to describe the products the tool works with.
The notice appears in the README, on the start page of the local interface, in the report overview and in the help dialog.
The project does not use logos, colors or artwork of the trademark owners.

## Third-party components
- The report embeds Cytoscape.js, dagre and cytoscape-dagre (MIT license). Copyright and license notices are kept in
  `nsviz/assets/vendor/` and in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
- Optional sample configurations come from a third-party project under the Apache License 2.0. They are not part of this
  repository and are downloaded on the user's machine on request ([SOURCES.md](SOURCES.md)).
- Vendor documentation is not copied. Rule texts are written independently and refer to their sources by name.

## References to standards and vendor guidance
Rules refer to BSI IT-Grundschutz modules, BSI TR-02102-2 and the vendor's secure deployment guidance at topic level,
without requirement IDs. The assignment is a technical classification. Before using it in an audit, check it against the
current edition of the document. The tool does not certify compliance; its category is called "compliance hints".

## Customer data and data protection
Configurations can contain personal data, such as user names, e-mail addresses, IP addresses and LDAP names, and are
confidential to the customer. Processing on behalf of a customer should follow the engagement contract, any
non-disclosure agreement and, where applicable, a data processing agreement. The tool processes everything locally; see
[PRIVACY.md](PRIVACY.md) for the handling concept. Masking of secrets is pattern based and not a guarantee.

## Warranty and liability
The software is provided "as is" (see [LICENSE](../LICENSE)). Results are automated hints. Recommendations to customers
remain the professional responsibility of the person using the tool.

## Rights
Copyright (c) 2026 ITCMA GmbH. All rights reserved. No license is granted for use, copying, modification or distribution
without the written permission of the rights holder.
