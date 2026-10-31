"""
Dynamic SVG Security Badge Generator.
Produces high-quality SVG shields (inspired by shields.io) representing domain security grades.
"""

def generate_svg_badge(grade: str, score: int, color_type: str = "emerald") -> str:
    """
    Generates a crisp, vector SVG trust badge.
    """
    colors = {
        "emerald": {"bg": "#10b981", "glow": "rgba(16, 185, 129, 0.4)"},
        "cyan": {"bg": "#06b6d4", "glow": "rgba(6, 182, 212, 0.4)"},
        "amber": {"bg": "#f59e0b", "glow": "rgba(245, 158, 11, 0.4)"},
        "orange": {"bg": "#f97316", "glow": "rgba(249, 115, 22, 0.4)"},
        "red": {"bg": "#ef4444", "glow": "rgba(239, 68, 68, 0.4)"},
        "gray": {"bg": "#64748b", "glow": "rgba(100, 116, 139, 0.4)"}
    }
    theme = colors.get(color_type, colors["emerald"])
    grade_text = f"{grade} ({score}%)" if score >= 0 else grade

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="180" height="28" viewBox="0 0 180 28" role="img" aria-label="Audite Security: {grade_text}">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="180" height="28" rx="6" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <rect width="95" height="28" fill="#0f172a"/>
    <rect x="95" width="85" height="28" fill="{theme['bg']}"/>
    <rect width="180" height="28" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <g font-weight="600" fill="#f8fafc">
      <svg x="8" y="6" width="16" height="16" fill="none" stroke="#10b981" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
      </svg>
      <text x="54" y="18" fill="#e2e8f0" font-size="11" letter-spacing="0.5">SÉCURITÉ</text>
    </g>
    <text x="137" y="18" font-weight="700" fill="#0f172a" font-size="11">{grade_text}</text>
  </g>
</svg>"""

