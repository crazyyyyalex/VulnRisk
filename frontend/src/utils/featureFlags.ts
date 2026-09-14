export interface FeatureFlags {
  // Core features
  risk_assessment: boolean;
  batch_processing: boolean;
  advanced_analytics: boolean;
  ai_risk_prediction: boolean;
  scanner_integrations: boolean;
  fedramp_compliance: boolean;
  
  // Demo features
  demo_features: {
    fedramp_compliance: boolean;
    ai_insights: boolean;
    scanner_integrations: boolean;
    advanced_analytics: boolean;
    batch_processing: boolean;
  };
  
  // Configuration
  free_cve_allowance: number;
  api_key_management: boolean;
}

class FeatureFlagManager {
  private flags: FeatureFlags | null = null;

  async loadFlags(): Promise<FeatureFlags> {
    if (this.flags) {
      return this.flags;
    }

    try {
      const response = await fetch('/api/v1/config/features');
      if (response.ok) {
        this.flags = await response.json();
      } else {
        // Fallback to default flags
        this.flags = this.getDefaultFlags();
      }
    } catch (error) {
      console.warn('Failed to load feature flags, using defaults:', error);
      this.flags = this.getDefaultFlags();
    }

    return this.flags;
  }

  private getDefaultFlags(): FeatureFlags {
    return {
      // Core features - enabled by default
      risk_assessment: true,
      batch_processing: true,
      advanced_analytics: true,
      ai_risk_prediction: true,
      scanner_integrations: true,
      fedramp_compliance: true,
      
      // Demo features - enabled in production for demo purposes
      demo_features: {
        fedramp_compliance: true,
        ai_insights: true,
        scanner_integrations: true,
        advanced_analytics: true,
        batch_processing: true,
      },
      
      // Configuration
      free_cve_allowance: 5, // 5 free CVEs in production
      api_key_management: true,
    };
  }

  isFeatureEnabled(featureKey: keyof FeatureFlags): boolean {
    if (!this.flags) return true; // Default to enabled during loading
    return this.flags[featureKey] === true;
  }

  isDemoFeature(featureKey: keyof FeatureFlags['demo_features']): boolean {
    if (!this.flags) return false;
    return this.flags.demo_features[featureKey] === true;
  }

  getFreeCVEAllowance(): number {
    if (!this.flags) return 5;
    return this.flags.free_cve_allowance;
  }

  isAPIKeyManagementEnabled(): boolean {
    if (!this.flags) return true;
    return this.flags.api_key_management;
  }
}

export const featureFlags = new FeatureFlagManager();

// Convenience functions for easier imports
export const getFeatureFlags = () => featureFlags.loadFlags();
export const isDemoFeature = (featureKey: keyof FeatureFlags['demo_features']) => featureFlags.isDemoFeature(featureKey);
export const getDemoFeatures = () => featureFlags.flags?.demo_features || {}; 