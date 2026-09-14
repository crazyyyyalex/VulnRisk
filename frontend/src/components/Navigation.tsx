import React, { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth0 } from '@auth0/auth0-react';
import { Logo } from './ui/logo';
import { DarkModeToggle } from './ui/dark-mode-toggle';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { ChevronDown, Menu, X, LogIn, LogOut, User } from 'lucide-react';
import { getFeatureFlags, isDemoFeature } from '../utils/featureFlags';

interface NavigationProps {
  className?: string;
}

export const Navigation: React.FC<NavigationProps> = ({ className = '' }) => {
  const location = useLocation();
  const { isAuthenticated, loginWithRedirect, logout, user } = useAuth0();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isFeaturesOpen, setIsFeaturesOpen] = useState(false);
  const [featureFlags, setFeatureFlags] = useState<any>(null);
  const featuresRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const loadFlags = async () => {
      const flags = await getFeatureFlags();
      setFeatureFlags(flags);
    };
    loadFlags();
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (featuresRef.current && !featuresRef.current.contains(event.target as Node)) {
        setIsFeaturesOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const isActive = (path: string) => location.pathname === path;

  const navItems = [
    { path: '/', label: 'Home' },
    { path: '/risk-assessment', label: 'Risk Assessment' },
    { path: '/about', label: 'About' },
  ];

  const demoFeatures = [
    { path: '/batch', label: 'Batch Processing', badge: 'Demo' },
    { path: '/analytics', label: 'Analytics', badge: 'Demo' },
    { path: '/ai-insights', label: 'AI Insights', badge: 'Demo' },
    { path: '/scanner-integrations', label: 'Scanner Integrations', badge: 'Demo' },
  ];

  return (
    <nav className={`bg-dark-500 border-b border-dark-400 ${className}`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <div className="flex items-center">
            <Link to="/" className="flex items-center">
              <Logo variant="text" size="lg" className="text-white" />
            </Link>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            {/* Main Navigation Items */}
            {navItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className={`text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive(item.path) ? 'text-primary-400 border-b-2 border-primary-400' : ''
                }`}
              >
                {item.label}
              </Link>
            ))}

            {/* Features Dropdown */}
            <div className="relative" ref={featuresRef}>
              <Button
                variant="ghost"
                className="text-gray-300 hover:text-white px-3 py-2 text-sm font-medium"
                onClick={() => setIsFeaturesOpen(!isFeaturesOpen)}
              >
                Features
                <ChevronDown className="ml-1 h-4 w-4" />
              </Button>
              
              {isFeaturesOpen && (
                <div className="absolute right-0 mt-2 w-64 bg-white dark:bg-dark-400 rounded-md shadow-lg py-1 z-50">
                  {demoFeatures.map((feature) => (
                    <Link
                      key={feature.path}
                      to={feature.path}
                      className="flex items-center justify-between px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-300"
                      onClick={() => setIsFeaturesOpen(false)}
                    >
                      <span>{feature.label}</span>
                      <Badge 
                        variant="secondary" 
                        className={feature.badge === 'RFC Pending' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'}
                      >
                        {feature.badge}
                      </Badge>
                    </Link>
                  ))}
                </div>
              )}
            </div>

            
          </div>

          {/* Right side - Auth & Dark mode toggle */}
          <div className="flex items-center space-x-4">
            {/* Authentication */}
            {isAuthenticated ? (
              <div className="flex items-center space-x-3">
                <div className="flex items-center space-x-2 text-gray-300">
                  <User className="h-4 w-4" />
                  <span className="text-sm">{user?.name || user?.email}</span>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => logout({ logoutParams: { returnTo: window.location.origin } })}
                  className="text-gray-300 hover:text-white"
                >
                  <LogOut className="h-4 w-4 mr-1" />
                  Sign Out
                </Button>
              </div>
            ) : (
              <Button
                variant="outline"
                size="sm"
                onClick={() => loginWithRedirect()}
                className="text-primary-400 border-primary-400 hover:bg-primary-400 hover:text-white"
              >
                <LogIn className="h-4 w-4 mr-1" />
                Client Portal
              </Button>
            )}
            
            <DarkModeToggle />
            
            {/* Mobile menu button */}
            <Button
              variant="ghost"
              className="md:hidden text-gray-300 hover:text-white"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
              {isMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </Button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden">
            <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3 bg-dark-400 rounded-md mt-2">
              {/* Main Navigation Items */}
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`block px-3 py-2 rounded-md text-base font-medium transition-colors ${
                    isActive(item.path) 
                      ? 'text-primary-400 bg-dark-300' 
                      : 'text-gray-300 hover:text-white hover:bg-dark-300'
                  }`}
                  onClick={() => setIsMenuOpen(false)}
                >
                  {item.label}
                </Link>
              ))}

              {/* Demo Features */}
              <div className="border-t border-dark-300 pt-2 mt-2">
                <div className="px-3 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Demo Features
                </div>
                {demoFeatures.map((feature) => (
                  <Link
                    key={feature.path}
                    to={feature.path}
                    className="flex items-center justify-between px-3 py-2 rounded-md text-base font-medium text-gray-300 hover:text-white hover:bg-dark-300"
                    onClick={() => setIsMenuOpen(false)}
                  >
                    <span>{feature.label}</span>
                    <Badge 
                      variant="secondary" 
                      className={feature.badge === 'RFC Pending' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'}
                    >
                      {feature.badge}
                    </Badge>
                  </Link>
                ))}
              </div>

              {/* Authentication */}
              <div className="border-t border-dark-300 pt-2 mt-2">
                {isAuthenticated ? (
                  <div className="px-3 py-2">
                    <div className="flex items-center space-x-2 text-gray-300 mb-2">
                      <User className="h-4 w-4" />
                      <span className="text-sm">{user?.name || user?.email}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        logout({ logoutParams: { returnTo: window.location.origin } });
                        setIsMenuOpen(false);
                      }}
                      className="w-full text-gray-300 hover:text-white hover:bg-dark-300"
                    >
                      <LogOut className="h-4 w-4 mr-1" />
                      Sign Out
                    </Button>
                  </div>
                ) : (
                  <div className="px-3 py-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        loginWithRedirect();
                        setIsMenuOpen(false);
                      }}
                      className="w-full text-primary-400 border-primary-400 hover:bg-primary-400 hover:text-white"
                    >
                      <LogIn className="h-4 w-4 mr-1" />
                      Client Portal
                    </Button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
}; 