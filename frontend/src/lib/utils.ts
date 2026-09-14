import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// API Call utility with authentication
export async function apiCall<T = any>(
  url: string, 
  options: RequestInit = {},
  getAccessTokenSilently?: () => Promise<string>
): Promise<T> {
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  // Add API Gateway key if available
  const apiKey = import.meta.env.VITE_API_GATEWAY_KEY;
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }

  // Add Auth0 token if available
  if (getAccessTokenSilently) {
    try {
      const token = await getAccessTokenSilently();
      headers['Authorization'] = `Bearer ${token}`;
    } catch (authError) {
      console.warn('Could not get auth token, proceeding without authentication');
    }
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    throw new Error(`API call failed: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

// Check if API key is configured
export function isApiKeyConfigured(): boolean {
  return !!import.meta.env.VITE_API_GATEWAY_KEY;
} 