"""
Audite - Lanceur Principal de la Plateforme d'Audit de Sécurité Web.
Démarre le serveur FastAPI et sert à la fois l'API et l'Interface Web sur http://localhost:8000
"""

import sys
import webbrowser
import uvicorn

# Ensure UTF-8 stdout encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    print("=" * 65)
    print(" [*] AUDITE - SCANNER DE SECURITE WEB & REMEDIATIONS")
    print("=" * 65)
    print(" >> Interface Web : http://localhost:8000")
    print(" >> Documentation API Swagger : http://localhost:8000/docs")
    print(" >> Appuyez sur CTRL+C pour arreter le serveur.")
    print("=" * 65)

    try:
        webbrowser.open("http://localhost:8000")
    except Exception:
        pass

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

if __name__ == "__main__":
    main()

