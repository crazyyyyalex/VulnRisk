// VulnRisk Brand Identity Configuration
export const BRAND_CONFIG = {
  // Company Identity
  name: "VulnRisk",
  tagline: "Transparent Vulnerability Risk Assessment",
  description: "Enterprise-grade vulnerability risk scoring with full transparency and explainable methodology.",
  
  // Color Palette - Updated to match user's new colors
  colors: {
    primary: {
      50: '#f0fdfa', 100: '#ccfbf1', 200: '#99f6e4', 300: '#5eead4', 400: '#2dd4bf', 500: '#35dba7', // Primary Teal
      600: '#0d9488', 700: '#0f766e', 800: '#115e59', 900: '#134e4a',
    },
    secondary: {
      50: '#f6f5f8', 100: '#f1f5f9', 200: '#e2e8f0', 300: '#cbd5e1', 400: '#9b879f', 500: '#64748b', // Secondary Purple
      600: '#475569', 700: '#334155', 800: '#1e293b', 900: '#0f172a',
    },
    accent: {
      50: '#fdf2f8', 100: '#fce7f3', 200: '#fbcfe8', 300: '#f9a8d4', 400: '#f472b6', 500: '#eb74c6', // Accent Pink
      600: '#db2777', 700: '#be185d', 800: '#9d174d', 900: '#831843',
    },
    success: {
      50: '#f0fdf4', 100: '#dcfce7', 200: '#bbf7d0', 300: '#86efac', 400: '#4ade80', 500: '#50e96f', // Success Green
      600: '#16a34a', 700: '#15803d', 800: '#166534', 900: '#14532d',
    },
    warning: {
      50: '#fffbeb', 100: '#fef3c7', 200: '#fde68a', 300: '#fcd34d', 400: '#fbbf24', 500: '#f59e0b', // Warning Amber
      600: '#d97706', 700: '#b45309', 800: '#92400e', 900: '#78350f',
    },
    neutral: {
      50: '#fafafa', 100: '#f5f5f5', 200: '#e5e5e5', 300: '#d4d4d4', 400: '#a3a3a3', 500: '#737373', 600: '#525252', 700: '#404040', 800: '#262626', 900: '#171717',
    },
    dark: {
      50: '#0c0c2b', 100: '#0c0c2b', 200: '#0c0c2b', 300: '#0c0c2b', 400: '#0c0c2b', 500: '#0c0c2b', // Dark Background
      600: '#0c0c2b', 700: '#0c0c2b', 800: '#0c0c2b', 900: '#0c0c2b',
    }
  },
  
  // Typography
  typography: {
    fontFamily: {
      sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      mono: ['JetBrains Mono', 'Fira Code', 'Monaco', 'Consolas', 'monospace'],
      display: ['Inter', 'system-ui', 'sans-serif'],
      serif: ['Georgia', 'Times', 'serif'],
    },
    fontSize: {
      xs: '0.75rem', sm: '0.875rem', base: '1rem', lg: '1.125rem', xl: '1.25rem', '2xl': '1.5rem', '3xl': '1.875rem', '4xl': '2.25rem', '5xl': '3rem', '6xl': '3.75rem', '7xl': '4.5rem', '8xl': '6rem', '9xl': '8rem',
    },
    fontWeight: {
      light: '300', normal: '400', medium: '500', semibold: '600', bold: '700', extrabold: '800', black: '900',
    }
  },
  
  // Spacing & Layout
  spacing: {
    xs: '0.25rem', sm: '0.5rem', md: '1rem', lg: '1.5rem', xl: '2rem', '2xl': '3rem', '3xl': '4rem', '4xl': '6rem', '5xl': '8rem',
  },
  
  // Border Radius
  borderRadius: {
    none: '0', sm: '0.125rem', base: '0.25rem', md: '0.375rem', lg: '0.5rem', xl: '0.75rem', '2xl': '1rem', '3xl': '1.5rem', full: '9999px',
  },
  
  // Shadows
  shadows: {
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)', base: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)', md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)', lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)', xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)', '2xl': '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
  }
};

export const PRIORITY_COLORS = {
  CRITICAL: BRAND_CONFIG.colors.accent[500],
  HIGH: BRAND_CONFIG.colors.warning[500],
  MEDIUM: BRAND_CONFIG.colors.warning[400],
  LOW: BRAND_CONFIG.colors.success[500],
  INFORMATIONAL: BRAND_CONFIG.colors.secondary[400],
};

export const STATUS_COLORS = {
  success: BRAND_CONFIG.colors.success[500],
  warning: BRAND_CONFIG.colors.warning[500],
  error: BRAND_CONFIG.colors.accent[500],
  info: BRAND_CONFIG.colors.primary[500],
};