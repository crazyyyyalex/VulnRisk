import React, { useEffect } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent } from './ui/card';
import { Loader2 } from 'lucide-react';

interface AppState {
  returnTo?: string;
}

const AuthCallback: React.FC = () => {
  const { isAuthenticated, isLoading, error, user } = useAuth0();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLoading) {
      if (isAuthenticated) {
        // Get the return URL from Auth0 appState or default to risk assessment
        const appState = (window as any).__AUTH0_APP_STATE__ as AppState;
        const returnTo = appState?.returnTo || '/risk-assessment';
        navigate(returnTo, { replace: true });
      } else if (error) {
        // Handle authentication error
        console.error('Authentication error:', error);
        navigate('/', { replace: true });
      }
    }
  }, [isAuthenticated, isLoading, error, navigate]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <Card className="w-96">
          <CardContent className="flex flex-col items-center justify-center p-8">
            <Loader2 className="h-8 w-8 animate-spin text-primary-500 mb-4" />
            <h2 className="text-xl font-semibold mb-2">Authenticating...</h2>
            <p className="text-gray-600 text-center">
              Please wait while we complete your authentication.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return null;
};

export default AuthCallback; 