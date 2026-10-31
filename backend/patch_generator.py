"""
Unified Auto-Patch Generator.
Compiles all identified security weaknesses for a domain into a single,
clean, drop-in configuration file tailored to the user's specific web server.
"""

import json
from typing import Dict, Any, List


def generate_unified_patch(findings: List[Dict[str, Any]], platform: str = "firebase") -> Dict[str, str]:
    """
    Synthesizes all missing security headers and rules into a single production-ready configuration file.
    """
    platform = platform.lower().strip()
    
    # Identify what needs fixing
    needs_hsts = any("hsts" in f.get("key", "").lower() and f.get("status") != "pass" for f in findings)
    needs_csp = any("content-security-policy" in f.get("key", "").lower() and f.get("status") != "pass" for f in findings)
    needs_xfo = any("x-frame-options" in f.get("key", "").lower() and f.get("status") != "pass" for f in findings)
    needs_xcto = any("x-content-type-options" in f.get("key", "").lower() and f.get("status") != "pass" for f in findings)
    needs_referrer = any("referrer-policy" in f.get("key", "").lower() and f.get("status") != "pass" for f in findings)
    needs_permissions = any("permissions-policy" in f.get("key", "").lower() and f.get("status") != "pass" for f in findings)
    needs_coop = any("cross-origin-opener-policy" in f.get("key", "").lower() and f.get("status") != "pass" for f in findings)
    needs_corp = any("cross-origin-resource-policy" in f.get("key", "").lower() and f.get("status") != "pass" for f in findings)

    # 1. VERCEL (vercel.json) - Compatible Supabase
    if platform == "vercel":
        header_items = []
        if needs_hsts:
            header_items.append({"key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload"})
        if needs_csp:
            header_items.append({"key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://*.supabase.co wss://*.supabase.co;"})
        if needs_xfo:
            header_items.append({"key": "X-Frame-Options", "value": "SAMEORIGIN"})
        if needs_xcto:
            header_items.append({"key": "X-Content-Type-Options", "value": "nosniff"})
        if needs_referrer:
            header_items.append({"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"})
        if needs_permissions:
            header_items.append({"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()"})

        config = {
            "headers": [
                {
                    "source": "/(.*)",
                    "headers": header_items
                }
            ]
        }
        return {
            "filename": "vercel.json",
            "language": "json",
            "content": json.dumps(config, indent=2)
        }

    # 2. FIREBASE HOSTING (firebase.json)
    elif platform == "firebase":
        header_items = []
        if needs_hsts:
            header_items.append({"key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload"})
        if needs_csp:
            header_items.append({"key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https://apis.google.com https://www.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:;"})
        if needs_xfo:
            header_items.append({"key": "X-Frame-Options", "value": "SAMEORIGIN"})
        if needs_xcto:
            header_items.append({"key": "X-Content-Type-Options", "value": "nosniff"})
        if needs_referrer:
            header_items.append({"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"})
        if needs_permissions:
            header_items.append({"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()"})
        if needs_coop:
            header_items.append({"key": "Cross-Origin-Opener-Policy", "value": "same-origin-allow-popups"})
        if needs_corp:
            header_items.append({"key": "Cross-Origin-Resource-Policy", "value": "same-origin"})

        config = {
            "hosting": {
                "public": "build",
                "ignore": ["firebase.json", "**/.*", "**/node_modules/**"],
                "headers": [
                    {
                        "source": "/**",
                        "headers": header_items
                    }
                ]
            }
        }
        return {
            "filename": "firebase.json",
            "language": "json",
            "content": json.dumps(config, indent=2)
        }

    # 2. NGINX (/etc/nginx/conf.d/security-headers.conf)
    elif platform == "nginx":
        lines = [
            "# ===========================================================",
            "# Patch de durcissement généré par Audite Security Engine",
            "# À inclure dans vos blocs 'server { ... }' :",
            "# include /etc/nginx/conf.d/security-headers.conf;",
            "# ===========================================================",
            "",
            "# Masquage de la version Nginx",
            "server_tokens off;",
            ""
        ]
        if needs_hsts:
            lines.append('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;')
        if needs_csp:
            lines.append('add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; font-src \'self\' data:;" always;')
        if needs_xfo:
            lines.append('add_header X-Frame-Options "SAMEORIGIN" always;')
        if needs_xcto:
            lines.append('add_header X-Content-Type-Options "nosniff" always;')
        if needs_referrer:
            lines.append('add_header Referrer-Policy "strict-origin-when-cross-origin" always;')
        if needs_permissions:
            lines.append('add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;')
        if needs_coop:
            lines.append('add_header Cross-Origin-Opener-Policy "same-origin" always;')
        if needs_corp:
            lines.append('add_header Cross-Origin-Resource-Policy "same-origin" always;')

        lines.extend([
            "",
            "# Protection contre l'accès aux répertoires sensibles",
            "location ~ /\\.(?!well-known) {",
            "    deny all;",
            "    return 404;",
            "}"
        ])
        return {
            "filename": "security-headers.conf",
            "language": "nginx",
            "content": "\n".join(lines)
        }

    # 3. APACHE (.htaccess)
    elif platform == "apache":
        lines = [
            "# ===========================================================",
            "# Patch de sécurité généré par Audite pour Apache (.htaccess)",
            "# ===========================================================",
            "<IfModule mod_headers.c>"
        ]
        if needs_hsts:
            lines.append('    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"')
        if needs_csp:
            lines.append('    Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:;"')
        if needs_xfo:
            lines.append('    Header always set X-Frame-Options "SAMEORIGIN"')
        if needs_xcto:
            lines.append('    Header always set X-Content-Type-Options "nosniff"')
        if needs_referrer:
            lines.append('    Header always set Referrer-Policy "strict-origin-when-cross-origin"')
        if needs_permissions:
            lines.append('    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"')
        lines.extend([
            "</IfModule>",
            "",
            "# Masquage des bannières Apache",
            "ServerSignature Off",
            "",
            "# Bloquer les fichiers sensibles (.git, .env)",
            '<FilesMatch "^\\.(?!well-known)">',
            "    Require all denied",
            "</FilesMatch>"
        ])
        return {
            "filename": ".htaccess",
            "language": "apache",
            "content": "\n".join(lines)
        }

    # 4. NODE.JS / EXPRESS (security.js)
    elif platform in ["nodejs", "node", "express"]:
        content = """// Middleware de sécurité généré par Audite Security Engine
// Installation préalable requise : npm install helmet
const helmet = require('helmet');

function configureSecurity(app) {
  // Masquage de l'empreinte Express
  app.disable('x-powered-by');

  // Configuration complète des en-têtes de protection
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      frameguard: { action: 'sameorigin' },
      noSniff: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    })
  );
}

module.exports = configureSecurity;"""
        return {
            "filename": "security.js",
            "language": "javascript",
            "content": content
        }

    # 5. SUPABASE (supabase-security.ts & RLS)
    elif platform == "supabase":
        content = """// supabase/functions/_shared/security-headers.ts
// Configuration de sécurité générée par Audite Security Engine pour Supabase Edge Functions

export const securityHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Frame-Options': 'SAMEORIGIN',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Content-Security-Policy': "default-src 'self'; connect-src 'self' https://*.supabase.co wss://*.supabase.co;"
};

/**
 * [SECURITE] GUIDE DE DURCISSEMENT SUPABASE (OWASP & ANSSI) :
 * 
 * 1. CLÉS D'AUTHENTIFICATION :
 *    - La clé `anon` est publique : elle est sécurisée UNIQUEMENT si le RLS est actif.
 *    - La clé `service_role` est SECRÈTE : ne JAMAIS l'utiliser dans React/Vue/Svelte ou Next.js client-side.
 *    - N'utilisez `service_role` que dans les Edge Functions ou serveurs privés.
 * 
 * 2. ACTIVATION DU ROW LEVEL SECURITY (RLS) DANS SUPABASE SQL EDITOR :
 *    ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
 *    CREATE POLICY "Les utilisateurs ne modifient que leur profil"
 *      ON public.profiles FOR ALL
 *      USING (auth.uid() = id);
 */
"""
        return {
            "filename": "supabase-security.ts",
            "language": "typescript",
            "content": content
        }

    # 6. NEXT.JS (next.config.js)
    else:
        content = """// next.config.js - Configuration des en-têtes générée par Audite
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self';".replace(/\\s{2,}/g, ' ').trim()
  }
];

module.exports = {
  poweredByHeader: false, // Supprime X-Powered-By: Next.js
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};"""
        return {
            "filename": "next.config.js",
            "language": "javascript",
            "content": content
        }

