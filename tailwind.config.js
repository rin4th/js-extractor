/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,svelte}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#05070d',
          900: '#070b14',
          850: '#0b1120',
          800: '#111827',
        },
        signal: {
          DEFAULT: '#34d399',
          dim: '#10b981',
          glow: '#6ee7b7',
        },
      },
      boxShadow: {
        signal: '0 0 0 1px rgb(52 211 153 / 0.2), 0 0 32px rgb(16 185 129 / 0.09)',
        glow: '0 0 0 1px rgb(52 211 153 / 0.16), 0 0 24px rgb(52 211 153 / 0.16)',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Cascadia Code', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      backgroundImage: {
        'cyber-grid':
          'linear-gradient(rgb(52 211 153 / 0.035) 1px, transparent 1px), linear-gradient(90deg, rgb(52 211 153 / 0.035) 1px, transparent 1px)',
      },
      keyframes: {
        pulseSignal: {
          '0%, 100%': { opacity: '0.45' },
          '50%': { opacity: '1' },
        },
      },
      animation: {
        'pulse-signal': 'pulseSignal 1.5s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
