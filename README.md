# 🛡️ Audite - Plateforme d'Audit de Sécurité Web & Guide de Remédiation

> **Audite** est un outil complet d'analyse passive des vulnérabilités web conforme aux standards **OWASP** et **ANSSI**, conçu pour diagnostiquer les faiblesses de sécurité de n'importe quel site web et fournir les configurations pas-à-pas pour les corriger.

---

## 🚀 Démarrage Rapide

### Option 1 : Double-clic direct sous Windows
Double-cliquez simplement sur le fichier **`demarrer.bat`**. Le serveur se lancera et votre navigateur s'ouvrira automatiquement sur `http://localhost:8000`.

### Option 2 : En ligne de commande
```bash
# Installation des dépendances (déjà effectuée) :
pip install -r backend/requirements.txt

# Lancement de l'application :
python run.py
```

L'application est immédiatement accessible sur :
* **Interface Web :** [http://localhost:8000](http://localhost:8000)
* **Documentation interactive API (Swagger) :** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🔍 Les 4 Moteurs d'Audit Intégrés

1. **En-têtes HTTP de Sécurité (`scanners/headers.py`)** :
   * `Strict-Transport-Security` (HSTS, max-age, includeSubDomains, preload)
   * `Content-Security-Policy` (CSP, détection des directives permissives `unsafe-inline`)
   * `X-Frame-Options` (Protection anti-Clickjacking)
   * `X-Content-Type-Options` (Protection contre le MIME-sniffing)
   * `Referrer-Policy` (Confidentialité des URL)
   * `Permissions-Policy` (Restriction micro, caméra, géolocalisation)
   * Attributs de sécurité des cookies (`Secure`, `HttpOnly`, `SameSite`)

2. **Chiffrement SSL/TLS (`scanners/ssl_scanner.py`)** :
   * Validité et date d'expiration du certificat X.509
   * Autorité de certification (Let's Encrypt, DigiCert, Cloudflare, etc.)
   * Version du protocole négocié (TLS 1.2, TLS 1.3 vs protocoles obsolètes)
   * Suites cryptographiques et taille des clés de chiffrement (128 / 256 bits)

3. **DNS & Anti-Usurpation (`scanners/dns_scanner.py`)** :
   * Configuration de l'enregistrement **SPF** (`v=spf1`, conformité des mécanismes `~all` / `-all`)
   * Politique **DMARC** (`v=DMARC1`, détection des politiques faibles `p=none` vs strictes `p=reject`)
   * Signature **DNSSEC** (protection contre le DNS Cache Poisoning)
   * Enregistrements MX et cohérence messagerie

4. **Exposition & Fuites d'Informations (`scanners/leaks_scanner.py`)** :
   * Détection des versions de serveurs dans les bannières (`Server: Apache/2.4.x`, `nginx/1.x`)
   * Empreintes technologiques superflues (`X-Powered-By: PHP`, `Express`)
   * Présence du fichier RFC 9116 (`/.well-known/security.txt`)
   * Protection passive des fichiers sensibles (`.env`, `.git`)

---

## 🛠️ Base de Connaissances & Remédiations Prêtes à l'Emploi

Pour chaque vulnérabilité ou avertissement détecté, Audite génère :
* L'explication du risque et les références **OWASP Top 10** et **CWE**.
* Des blocs de code prêts à copier pour :
  * **Nginx** (`add_header ...`)
  * **Apache** (`Header always set ...`)
  * **Cloudflare** (Règles Edge Certificates & Transform Rules)
  * **Node.js / Express** (Configuration Helmet)
  * **Next.js** (`next.config.js`)
* **Simulateur de Remédiation interactif :** cochez les correctifs appliqués directement dans l'interface pour voir votre note grimper en temps réel jusqu'à la note maximale **A+** !

---

## 🔒 Cadre Éthique & Sécurité

* Les analyses réalisées par Audite sont **strictement passives** (inspection des informations publiques renvoyées par le serveur lors d'une requête HTTP/TLS standard).
* Une protection **anti-SSRF** stricte est intégrée : les adresses IP privées (`127.0.0.1`, `10.x.x.x`, `192.168.x.x`, etc.) sont bloquées pour protéger l'infrastructure hôte.

