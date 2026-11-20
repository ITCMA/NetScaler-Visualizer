# Legal notes (hints, not legal advice)

🇩🇪 [Deutsche Version](LEGAL.de.md)

This is a technical checklist of points that should be looked at. It is **not legal advice** and makes no binding statements.
For anything binding (publication, commercial use, customer contracts), get a review by a lawyer.

## 1. Trademarks and the project name  – *highest risk*
- "NetScaler" and "Citrix" are trademarks of their respective owners (to be verified: currently attributed to Cloud Software Group, Inc.
  and/or affiliates). The report, README and license state that the project is independent and not affiliated or endorsed.
- A disclaimer does not by itself make the use of a mark permissible. Descriptive/referential use ("analyzer *for* NetScaler")
  is usually tolerated more than using the mark as the **product name** ("NetScaler Visualizer"), as repository/domain/package name,
  or with logos. Whether and how this is acceptable depends on jurisdiction and on the owner's brand guidelines – unverified.
- Risk grows if the project is public, commercial, or uses the owner's logos/colours/product artwork (it does not).
- **Proposal:** use a neutral product name and keep the mark only descriptively, e.g. *"<NeutralName> – configuration analyzer for
  NetScaler ADC"*. Candidate pattern: ADC-related neutral names (e.g. "adc-config-map", "adcscope", "confgraph") – **availability is
  not checked**; search trademark registers (DPMA, EUIPO, USPTO) and package/domain names before choosing. Python package `nsviz` and
  CLI name are already neutral; repository name and report title currently contain "NetScaler".
- Check the owner's current brand/trademark guidelines for third-party tools.

## 2. Third-party licenses
- Embedded libraries (Cytoscape.js, dagre, cytoscape-dagre) are MIT-licensed: keep the copyright and license notices
  (done in `nsviz/assets/vendor/` and `THIRD_PARTY_NOTICES.md`). The minified dagre build bundles graphlib and lodash; their exact versions and
  notices are still to be recorded.
- Test data comes from a third-party project under Apache-2.0 and is **not redistributed** (downloaded on the user's machine).
  If it is ever redistributed: include the license text, upstream NOTICE (if any), and mark changes (hex blobs zeroed).
  The origin of the content of those files is not verified.
- Vendor documentation and support articles are copyrighted: no text is copied; rule texts are own wording with source references.

## 3. Standards references (BSI)
- References name BSI IT-Grundschutz modules and BSI TR-02102-2 at topic level, not requirement IDs, and are **unverified** against the
  current editions. Before use in audits: verify against the current edition, cite edition and requirement IDs correctly, and do not
  reproduce BSI text beyond short quotations with attribution.
- The tool does not certify compliance. Avoid statements like "BSI-compliant"; the category is "compliance *hints*".

## 4. Data protection (GDPR) and confidentiality
- Configs may contain personal data (user/admin names, e-mail addresses, IPs, LDAP DNs) and are business-confidential for the customer.
  Processing happens on behalf of the customer: check the engagement contract/NDA and, where applicable, a data processing agreement.
- See [PRIVACY.md](PRIVACY.md): local processing, git-ignored private folder, anonymization before any development use, retention/deletion.
- Masking of secrets is pattern based and no guarantee.

## 5. Liability and warranty
- The license text disclaims warranty and liability ("as is"). Under German law, liability for intent cannot be excluded in advance,
  and limits for other cases depend on the contract type – the wording must be reviewed for the intended use. Results are automated hints;
  recommendations to customers remain the consultant's professional responsibility.

## 6. Ownership and license model
- Currently "all rights reserved", no open-source license. Clarify who holds the rights (author vs. employer/company; employment
  contract, side-activity rules) and whether customers may be given usage rights (license for deliverables).
- Before publishing code that others may reuse, decide on a license deliberately.

## 7. Further points to include in a legal review
- Export of encrypted/crypto-related content: not applicable to the tool itself; no crypto implemented.
- Obligations towards customers/employers regarding tools used for deliverables (disclosure, security requirements) – check contracts.
- Accessibility obligations may apply if the tool is offered commercially (e.g. EU accessibility rules); the UI follows common practice
  (keyboard, contrast, ARIA) but has no formal conformance audit.
