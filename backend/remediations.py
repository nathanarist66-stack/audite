"""
Knowledge Base of Actionable Security Remediations.
Provides explanations, OWASP/CWE references, and ready-to-use configuration snippets
for Nginx, Apache, Cloudflare, Node.js (Express/Helmet), and Next.js.
"""

from typing import Dict, Any

REMEDIATIONS_DB: Dict[str, Dict[str, Any]] = {
    "hsts": {
        "title": "Activer HSTS (Strict-Transport-Security)",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "why": "Sans HSTS, les utilisateurs peuvent être victimes d'une attaque 'Man-in-the-Middle' ou 'SSL Stripping'. HSTS force le navigateur à se connecter toujours en HTTPS, même si l'internaute tape http://.",
        "snippets": {
            "nginx": """# Dans le bloc 'server' HTTPS de votre configuration Nginx :
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;""",
            "apache": """# Dans le VirtualHost SSL de votre fichier Apache (.conf ou .htaccess) :
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload\"""",
            "cloudflare": """# Dans le tableau de bord Cloudflare :
SSL/TLS > Edge Certificates > Activer 'Always Use HTTPS' et 'HTTP Strict Transport Security (HSTS)'
Durée recommandée : 12 mois (31536000 s) avec sous-domaines et préchargement.""",
            "nodejs": """// Avec Express et le middleware Helmet :
import helmet from 'helmet';
app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
}));""",
            "nextjs": """// Dans next.config.js :
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
        ],
      },
    ];
  },
};""",
            "vercel": """// Dans vercel.json à la racine du projet :
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        }
      ]
    }
  ]
}""",
            "firebase": """// Dans votre fichier firebase.json (section hosting) :
"hosting": {
  "headers": [
    {
      "source": "/**",
      "headers": [
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        }
      ]
    }
  ]
}"""
        }
    },
    "csp": {
        "title": "Définir une politique CSP (Content-Security-Policy)",
        "owasp": "A03:2021 - Injection (XSS)",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "why": "La CSP est la défense numéro un contre les failles XSS. Elle interdit le chargement et l'exécution de code JavaScript ou d'images provenant de sources non autorisées.",
        "snippets": {
            "vercel": """// Dans vercel.json (compatible Supabase & Vercel) :
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://*.supabase.co wss://*.supabase.co;"
        }
      ]
    }
  ]
}""",
            "firebase": """// Dans votre fichier firebase.json (section hosting) :
"hosting": {
  "headers": [
    {
      "source": "/**",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https://apis.google.com https://www.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:;"
        }
      ]
    }
  ]
}""",
            "nginx": """# Exemple de CSP baseline pour Nginx :
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self';" always;""",
            "apache": """# Dans votre configuration Apache :
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self';\"""",
            "nodejs": """// Avec Helmet en Node.js :
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  })
);""",
            "nextjs": """// Dans next.config.js :
const cspHeader = `
    default-src 'self';
    script-src 'self' 'unsafe-eval' 'unsafe-inline';
    style-src 'self' 'unsafe-inline';
    img-src 'self' blob: data:;
    font-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
`.replace(/\\s{2,}/g, ' ').trim();

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: cspHeader }] }];
  }
};"""
        }
    },
    "x_frame_options": {
        "title": "Bloquer le Clickjacking (X-Frame-Options)",
        "owasp": "A04:2021 - Insecure Design",
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        "why": "Permet d'empêcher des attaquants d'intégrer votre site dans une balise iframe transparente sur leur propre site pour détourner les clics d'authentification ou de paiement.",
        "snippets": {
            "vercel": """// Dans vercel.json :
{ "key": "X-Frame-Options", "value": "SAMEORIGIN" }""",
            "firebase": """// Dans firebase.json :
{ "key": "X-Frame-Options", "value": "SAMEORIGIN" }""",
            "nginx": """# Pour interdire toute imbrication iframe :
add_header X-Frame-Options "DENY" always;

# OU autoriser uniquement votre propre domaine :
add_header X-Frame-Options "SAMEORIGIN" always;""",
            "apache": """Header always set X-Frame-Options "SAMEORIGIN\"""",
            "nodejs": """// Avec Express :
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});""",
            "nextjs": """{ key: 'X-Frame-Options', value: 'SAMEORIGIN' }"""
        }
    },
    "x_content_type_options": {
        "title": "Bloquer le MIME-Sniffing (X-Content-Type-Options)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-430: Deployment of Wrong Handler",
        "why": "Force le navigateur à faire confiance au Content-Type déclaré plutôt que d'analyser le contenu du fichier (ce qui pourrait transformer une image uploadée en script exécutable).",
        "snippets": {
            "vercel": """// Dans vercel.json :
{ "key": "X-Content-Type-Options", "value": "nosniff" }""",
            "firebase": """// Dans firebase.json :
{ "key": "X-Content-Type-Options", "value": "nosniff" }""",
            "nginx": """add_header X-Content-Type-Options "nosniff" always;""",
            "apache": """Header always set X-Content-Type-Options "nosniff\"""",
            "nodejs": """app.use(helmet.noSniff());""",
            "nextjs": """{ key: 'X-Content-Type-Options', value: 'nosniff' }"""
        }
    },
    "referrer_policy": {
        "title": "Sécuriser le Referrer (Referrer-Policy)",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "why": "Empêche que des jetons sensibles ou des identifiants présents dans l'URL ne soient divulgués à des sites externes.",
        "snippets": {
            "vercel": """// Dans vercel.json :
{ "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }""",
            "firebase": """// Dans firebase.json :
{ "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }""",
            "nginx": """add_header Referrer-Policy "strict-origin-when-cross-origin" always;""",
            "apache": """Header always set Referrer-Policy "strict-origin-when-cross-origin\"""",
            "nodejs": """app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));""",
            "nextjs": """{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }"""
        }
    },
    "permissions_policy": {
        "title": "Restreindre les API Navigateur (Permissions-Policy)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "why": "Désactive l'accès automatique des scripts tiers à la caméra, au microphone et à la géolocalisation de l'utilisateur.",
        "snippets": {
            "vercel": """// Dans vercel.json :
{ "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()" }""",
            "firebase": """// Dans firebase.json :
{ "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()" }""",
            "nginx": """add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;""",
            "apache": """Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()\"""",
            "nodejs": """res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');"""
        }
    },
    "server_tokens": {
        "title": "Masquer les versions et bannières du serveur",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "why": "Indiquer le numéro exact de version de votre serveur permet aux pirates de rechercher directement les exploits automatisés (CVE) associés.",
        "snippets": {
            "nginx": """# Dans le bloc http {} de /etc/nginx/nginx.conf :
server_tokens off;""",
            "apache": """# Dans /etc/apache2/conf-available/security.conf :
ServerTokens Prod
ServerSignature Off"""
        }
    },
    "x_powered_by": {
        "title": "Supprimer l'en-tête X-Powered-By",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200: Information Disclosure",
        "why": "Ne divulguez pas que vous utilisez Express, PHP ou ASP.NET afin de réduire la surface d'attaque.",
        "snippets": {
            "nodejs": """// Express :
app.disable('x-powered-by');""",
            "php": """// Dans php.ini :
expose_php = Off""",
            "nginx": """# Si Nginx sert de proxy :
proxy_hide_header X-Powered-By;"""
        }
    },
    "dns_spf": {
        "title": "Configurer un enregistrement DNS SPF",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-290: Authentication Bypass by Spoofing",
        "why": "Le SPF indique aux serveurs de messagerie quels serveurs IP ont le droit légitime d'envoyer des emails avec votre nom de domaine.",
        "snippets": {
            "dns": """# Exemple d'enregistrement TXT à la racine du domaine :
Nom : @ (ou mondomaine.fr)
Type : TXT
Valeur : v=spf1 include:_spf.google.com ~all
(ou -all pour une politique hardfail encore plus stricte)"""
        }
    },
    "dns_dmarc": {
        "title": "Configurer DMARC contre l'usurpation d'identité",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-290: Authentication Bypass by Spoofing",
        "why": "DMARC indique quoi faire si un email échoue les contrôles SPF/DKIM (rejet automatique ou mise en quarantaine) et vous envoie des rapports d'attaques.",
        "snippets": {
            "dns": """# Enregistrement DNS TXT :
Nom : _dmarc.mondomaine.fr
Type : TXT
Valeur : v=DMARC1; p=reject; rua=mailto:dmarc-reports@mondomaine.fr; pct=100;"""
        }
    },
    "block_sensitive_paths": {
        "title": "Bloquer l'accès aux répertoires sensibles (.git, .env)",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-552: Files or Directories Accessible to External Parties",
        "why": "Laisser fuiter un fichier .env ou un dossier .git donne un accès immédiat à vos clés API, mots de passe de base de données et code source.",
        "snippets": {
            "nginx": """# Bloquer tous les fichiers et dossiers cachés (.git, .env, etc.) :
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}""",
            "apache": """# Dans le fichier .htaccess ou virtualhost :
<FilesMatch "^\\.(?!well-known)">
    Require all denied
</FilesMatch>"""
        }
    },
    "ssl_certificate": {
        "title": "Installer et renouveler un certificat SSL valide",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-295: Improper Certificate Validation",
        "why": "Un certificat valide et actif garantit le chiffrement de bout en bout et évite l'affichage d'écrans d'alerte rouges bloquants dans les navigateurs.",
        "snippets": {
            "certbot": """# Générer et installer automatiquement avec Let's Encrypt (Certbot) :
sudo certbot --nginx -d votredomaine.fr -d www.votredomaine.fr

# Ou pour Apache :
sudo certbot --apache -d votredomaine.fr -d www.votredomaine.fr"""
        }
    },
    "ssl_protocols": {
        "title": "Durcir la configuration des protocoles SSL/TLS",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-326: Inadequate Encryption Strength",
        "why": "Les anciens protocoles (TLS 1.0, 1.1) contiennent des failles prouvées permettant le déchiffrement des communications.",
        "snippets": {
            "nginx": """ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;""",
            "apache": """SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES"""
        }
    },
    "update_js_libs": {
        "title": "Mettre à jour les bibliothèques JavaScript obsolètes",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "cwe": "CWE-1104: Use of Unmaintained Third Party Components",
        "why": "Les anciennes versions de frameworks JS (jQuery < 3.5, AngularJS 1.x, Bootstrap < 4.5) possèdent des failles XSS publiques facilement exploitables.",
        "snippets": {
            "html": """<!-- Mettre à jour vers la version stable de jQuery (3.7+) : -->
<script src="https://code.jquery.com/jquery-3.7.1.min.js" 
        integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" 
        crossorigin="anonymous"></script>""",
            "npm": """# Si vous utilisez un gestionnaire de paquets (Node / React / Vue) :
npm audit fix
# Ou mettre à jour explicitement :
npm install jquery@latest"""
        }
    },
    "enable_sri": {
        "title": "Activer Subresource Integrity (SRI) sur les CDN",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "cwe": "CWE-353: Missing Support for Integrity Check",
        "why": "Si un pirate ou un attaquant compromet le serveur CDN hébergeant votre bibliothèque externe, le hash SRI bloque immédiatement l'exécution du script altéré dans le navigateur de l'internaute.",
        "snippets": {
            "html": """<!-- Générer l'empreinte sha384 sur srihash.org et l'ajouter à vos balises : -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/mon-script.min.js"
        integrity="sha384-xxxx..."
        crossorigin="anonymous"></script>"""
        }
    },
    "secure_forms": {
        "title": "Sécuriser les formulaires et saisies d'identifiants",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "why": "Tout formulaire d'authentification doit obligatoirement transmettre les mots de passe via HTTPS vers un endpoint chiffré.",
        "snippets": {
            "html": """<!-- L'attribut action doit obligatoirement débuter par https:// : -->
<form action="https://monsite.fr/api/login" method="POST">
  <input type="email" name="email" required>
  <input type="password" name="password" required>
  <button type="submit">Connexion</button>
</form>"""
        }
    },
    "fix_mixed_content": {
        "title": "Éliminer le contenu mixte (Mixed Content)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-311: Missing Encryption of Sensitive Data",
        "why": "Le chargement de ressources HTTP sur une page HTTPS fragilise le cadenas SSL et permet l'altération du contenu par un attaquant réseau.",
        "snippets": {
            "html": """<!-- Remplacer les URL en http:// par https:// : -->
<img src="https://monsite.fr/images/logo.png">

<!-- Ou forcer automatiquement la mise à niveau via l'en-tête CSP : -->
Content-Security-Policy: upgrade-insecure-requests;"""
        }
    },
    "tabnabbing": {
        "title": "Corriger la faille Reverse Tabnabbing",
        "owasp": "A04:2021 - Insecure Design",
        "cwe": "CWE-1022: Improper Restriction of Rendered UI Layers or Frames",
        "why": "Sans rel='noopener', la page ouverte dans un nouvel onglet peut accéder à l'objet window.opener de votre site et le rediriger vers une fausse page de phishing.",
        "snippets": {
            "html": """<!-- Toujours associer rel="noopener noreferrer" aux liens avec target="_blank" : -->
<a href="https://site-externe.com" target="_blank" rel="noopener noreferrer">
  Visiter le partenaire
</a>"""
        }
    },
    "revoke_exposed_secrets": {
        "title": "Révoquer d'urgence les Clés Secrètes et Déplacer vers .env",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "why": "Une clé secrète (Stripe, GitHub, AWS, Supabase service_role) ne doit JAMAIS apparaître dans le code frontend ou les bundles JavaScript.",
        "snippets": {
            "vercel": """// 1. Définir la variable dans le dashboard Vercel (Project > Settings > Environment Variables)
// Exemple : STRIPE_SECRET_KEY=sk_live_...
// 2. Dans votre API Route (Next.js / Node.js) :
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
// NE JAMAIS préfixer avec NEXT_PUBLIC_ sinon la variable est envoyée au navigateur !""",
            "firebase": """// Utiliser Cloud Functions ou Firebase Functions Secrets :
// firebase functions:secrets:set STRIPE_SECRET_KEY
import { defineSecret } from 'firebase-functions/params';
const stripeSecret = defineSecret('STRIPE_SECRET_KEY');""",
            "supabase": """// 1. Révocation immédiate : Dashboard Supabase > Project Settings > API > Reset API Keys
// 2. Différence vitale :
// - 'anon' key : autorisée côté client (car bridée par le RLS Postgres).
// - 'service_role' key : STRICTEMENT RÉSERVÉE au backend / Edge Functions !
// 3. Dans vos Edge Functions Supabase (Deno) :
const supabase = createClient(
  Deno.env.get('SUPABASE_URL')!,
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')! // Accessible uniquement côté serveur
);""",
            "nodejs": """// 1. Installer dotenv : npm install dotenv
// 2. Dans votre fichier .env (exclu du Git via .gitignore) :
STRIPE_SECRET_KEY=sk_live_votre_cle_secrete
// 3. Côté serveur Node.js :
import 'dotenv/config';
const stripeSecret = process.env.STRIPE_SECRET_KEY;"""
        }
    },
    "cookie_consent": {
        "title": "Intégrer une bannière de consentement aux cookies (CMP)",
        "owasp": "A04:2021 - Insecure Design",
        "cwe": "CWE-359: Exposure of Private Personal Information",
        "why": "Le RGPD et la directive ePrivacy imposent de recueillir le consentement actif de l'internaute avant le déclenchement des cookies traceurs ou des pixels publicitaires.",
        "snippets": {
            "html": """<!-- Exemple d'intégration Axeptio (recommandé en France / UE) : -->
<script>
window.axeptioSettings = {
  clientId: "VOTRE_CLIENT_ID_AXEPTIO",
  cookiesVersion: "v1.0"
};
(function(d, s) {
  var t = d.getElementsByTagName(s)[0], e = d.createElement(s);
  e.async = true; e.src = "//static.axept.io/sdk.js";
  t.parentNode.insertBefore(e, t);
})(document, "script");
</script>""",
            "nextjs": """// Avec Next.js Script component dans layout.tsx :
import Script from 'next/script';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        {children}
        <Script src="https://static.axept.io/sdk.js" strategy="afterInteractive" />
      </body>
    </html>
  );
}"""
        }
    },
    "legal_notice": {
        "title": "Publier la Politique de Confidentialité & Mentions Légales",
        "owasp": "A04:2021 - Insecure Design",
        "cwe": "CWE-359: Exposure of Private Personal Information",
        "why": "L'absence de mentions légales et d'informations sur le responsable de traitement expose à des amendes réglementaires (CNIL).",
        "snippets": {
            "html": """<!-- Ajoutez un lien visible en pied de page vers vos mentions : -->
<footer class="footer">
  <a href="/politique-de-confidentialite">Politique de Confidentialité</a> |
  <a href="/mentions-legales">Mentions Légales</a>
</footer>"""
        }
    },
    "delist_ip_blacklist": {
        "title": "Demander le déréférencement des listes noires (Spamhaus / Barracuda)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693: Protection Mechanism Failure",
        "why": "Une IP inscrite sur liste noire bloque la réception de vos e-mails professionnels chez vos clients.",
        "snippets": {
            "dns": """# Étapes pour nettoyer votre IP :
1. Consultez le portail de délistage Spamhaus : https://check.spamhaus.org/
2. Consultez le portail Barracuda : https://www.barracudacentral.org/rbl/removal-request
3. Assurez-vous d'avoir configuré vos enregistrements SPF, DKIM et DMARC avant de soumettre la demande."""
        }
    },
    "sitemap_optimization": {
        "title": "Déployer un fichier sitemap.xml sécurisé",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "why": "Un sitemap exhaustif permet de cartographier toutes les pages publiques et garantit que seules des URLs en HTTPS sont indexées.",
        "snippets": {
            "nextjs": """// Dans app/sitemap.ts (Next.js App Router) :
import { MetadataRoute } from 'next';

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: 'https://monsite.fr',
      lastModified: new Date(),
      changeFrequency: 'weekly',
      priority: 1,
    },
    {
      url: 'https://monsite.fr/contact',
      lastModified: new Date(),
      changeFrequency: 'monthly',
      priority: 0.8,
    },
  ];
}"""
        }
    },
    "wp_disable_rest_users": {
        "title": "Désactiver l'énumération des utilisateurs WordPress",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "why": "L'API REST WordPress expose par défaut les logins d'administrateurs à l'adresse /wp-json/wp/v2/users, facilitant les attaques par force brute.",
        "snippets": {
            "apache": """# Dans le fichier functions.php de votre thème WordPress actif :
add_filter('rest_endpoints', function($endpoints) {
    if (!is_user_logged_in()) {
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']);
        }
    }
    return $endpoints;
});""",
            "nginx": """# Bloquer l'accès à l'endpoint users dans Nginx pour les visiteurs non connectés :
location ~* ^/wp-json/wp/v2/users {
    deny all;
    return 403;
}"""
        }
    },
    "wp_block_xmlrpc": {
        "title": "Bloquer l'accès au fichier xmlrpc.php",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-400: Uncontrolled Resource Consumption",
        "why": "XML-RPC est obsolète (remplacé par la REST API) et constitue la cible favorite des bots pour les attaques par déni de service et force brute amplifié.",
        "snippets": {
            "apache": """# Dans votre fichier .htaccess à la racine de WordPress :
<Files xmlrpc.php>
Order Allow,Deny
Deny from all
</Files>""",
            "nginx": """# Dans la configuration de votre bloc server Nginx :
location = /xmlrpc.php {
    deny all;
    access_log off;
    log_not_found off;
    return 403;
}"""
        }
    },
    "wp_hide_login": {
        "title": "Masquer et sécuriser la mire de connexion WordPress",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-307: Improper Restriction of Excessive Authentication Attempts",
        "why": "Laisser /wp-login.php ouvert expose votre site à des millions de tentatives de connexion automatisées par jour.",
        "snippets": {
            "apache": """# Recommandation :
# 1. Installez l'extension gratuite 'WPS Hide Login' pour déplacer la page de connexion
#    vers une URL secrète (ex: /mon-espace-secret-2026).
# 2. Installez 'Limit Login Attempts Reloaded' pour bloquer les IP après 3 échecs.
# 3. Activez l'authentification à deux facteurs (2FA) avec Wordfence ou WP 2FA."""
        }
    },
    "subdomains_exposure": {
        "title": "Protéger et cloisonner les sous-domaines sensibles",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "why": "Les sous-domaines de test (dev, staging, test) ou d'administration (admin, cpanel) sont fréquemment la porte d'entrée des pirates car ils sont moins surveillés que le site principal.",
        "snippets": {
            "nginx": """# Dans Nginx, restreindre l'accès à vos sous-domaines sensibles à votre seule IP :
allow 123.45.67.89; # Votre IP fixe
deny all;""",
            "apache": """# Dans le .htaccess de votre sous-domaine de test :
Require ip 123.45.67.89
# Ou exiger une authentification HTTP Basic Auth pour tous les visiteurs externes"""
        }
    }
}


def get_remediation(key: str) -> Dict[str, Any]:
    """Returns remediation details and snippets for a given finding key."""
    return REMEDIATIONS_DB.get(key, {
        "title": "Remédiation recommandée",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693: Protection Mechanism Failure",
        "why": "Corrigez cette mauvaise configuration pour respecter les recommandations de l'OWASP.",
        "snippets": {}
    })

