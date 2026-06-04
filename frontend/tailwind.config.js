/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "Fira Code", "monospace"],
      },
      colors: {
        surface:   "#080c12",
        panel:     "#0d1520",
        panelAlt:  "#0a1018",
        accent:    "#38bdf8",
        success:   "#22c55e",
        warning:   "#f59e0b",
        danger:    "#ef4444",
        muted:     "#64748b",
      },
      boxShadow: {
        glow:        "0 0 0 1px rgba(56, 189, 248, 0.14), 0 20px 48px rgba(2, 6, 23, 0.50)",
        "glow-red":  "0 0 0 1px rgba(239, 68, 68, 0.20), 0 12px 32px rgba(239, 68, 68, 0.08)",
        "glow-green":"0 0 0 1px rgba(34, 197, 94, 0.20), 0 12px 32px rgba(34, 197, 94, 0.08)",
        "inner-dark":"inset 0 1px 0 rgba(255,255,255,0.04)",
        "card":      "0 1px 3px rgba(0,0,0,0.5), 0 8px 24px rgba(0,0,0,0.3)",
      },
      backgroundImage: {
        grid: "linear-gradient(rgba(148,163,184,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.05) 1px, transparent 1px)",
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
      },
      animation: {
        "fade-in":  "fade-in 0.35s ease both",
        "slide-in": "slide-in 0.3s ease both",
        "counter":  "counter-up 0.25s ease both",
        "blink":    "blink 1.4s ease-in-out infinite",
      },
      keyframes: {
        "fade-in":    { from: { opacity: "0", transform: "translateY(10px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        "slide-in":   { from: { opacity: "0", transform: "translateX(-12px)" }, to: { opacity: "1", transform: "translateX(0)" } },
        "counter-up": { from: { transform: "translateY(6px)", opacity: "0" }, to: { transform: "translateY(0)", opacity: "1" } },
        "blink":      { "0%, 100%": { opacity: "1" }, "50%": { opacity: "0.3" } },
      },
      borderRadius: {
        "2xl": "1rem",
        "3xl": "1.25rem",
      },
      spacing: {
        "sidebar": "280px",
      },
    },
  },
  plugins: [],
};
