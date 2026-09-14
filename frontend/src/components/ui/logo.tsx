import React, { useEffect, useState } from 'react';

interface LogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  variant?: 'full' | 'icon' | 'text';
  className?: string;
  darkMode?: boolean;
}

export const Logo: React.FC<LogoProps> = ({ 
  size = 'md', 
  variant = 'full', 
  className = '',
  darkMode
}) => {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    // Check if dark mode is enabled
    const checkDarkMode = () => {
      const isDarkMode = document.documentElement.classList.contains('dark');
      setIsDark(isDarkMode);
    };

    checkDarkMode();

    // Listen for theme changes
    const observer = new MutationObserver(checkDarkMode);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class']
    });

    return () => observer.disconnect();
  }, []);

  const sizeClasses = {
    sm: 'h-6 w-6',
    md: 'h-8 w-8',
    lg: 'h-12 w-12',
    xl: 'h-16 w-16',
  };

  const textSizes = {
    sm: 'text-lg',
    md: 'text-xl',
    lg: 'text-2xl',
    xl: 'text-3xl',
  };

  // Use provided darkMode prop or auto-detect
  const shouldUseDarkMode = darkMode !== undefined ? darkMode : isDark;
  const logoSrc = shouldUseDarkMode ? '/logo/white.svg' : '/logo/dark.svg';

  if (variant === 'icon') {
    return (
      <div className={`relative ${sizeClasses[size]} ${className} bg-transparent dark:rounded-lg dark:overflow-hidden dark:bg-white/5 dark:ring-1 dark:ring-white/10 transition-colors`}>
        <img 
          src={logoSrc} 
          alt="VulnRisk Logo" 
          className="h-full w-full object-contain dark:mix-blend-screen"
        />
      </div>
    );
  }

  if (variant === 'text') {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <div className={`relative ${sizeClasses[size]} bg-transparent dark:rounded-lg dark:overflow-hidden dark:bg-white/5 dark:ring-1 dark:ring-white/10 transition-colors`}>
          <img 
            src={logoSrc} 
            alt="VulnRisk Logo" 
            className="h-full w-full object-contain dark:mix-blend-screen"
          />
        </div>
        <span className={`font-bold ${textSizes[size]} text-white dark:text-primary-400 transition-colors`}>
          VulnRisk
        </span>
      </div>
    );
  }

  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <div className={`relative ${sizeClasses[size]} bg-transparent dark:rounded-lg dark:overflow-hidden dark:bg-white/5 dark:ring-1 dark:ring-white/10 transition-colors`}>
        <img 
          src={logoSrc} 
          alt="VulnRisk Logo" 
          className="h-full w-full object-contain dark:mix-blend-screen"
        />
      </div>
      <div className="flex flex-col">
        <span className={`font-bold ${textSizes[size]} text-white dark:text-primary-400 leading-none transition-colors`}>
          VulnRisk
        </span>
        <span className="text-xs text-gray-500 dark:text-gray-300 font-medium leading-none">
          Risk Assessment
        </span>
      </div>
    </div>
  );
}; 