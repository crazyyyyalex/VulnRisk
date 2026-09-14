import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Logo } from '../components/ui/logo';
import { BRAND_CONFIG } from '../config/brand';
import { 
  Shield, 
  Brain, 
  Zap, 
  BarChart3, 
  FileText, 
  Users, 
  CheckCircle, 
  ArrowRight,
  Star,
  Award,
  TrendingUp,
  Lock,
  Eye,
  Target,
  Globe,
  GitBranch,
  Activity
} from 'lucide-react';

const HomePage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-secondary-50 to-primary-50 dark:from-dark-500 dark:to-dark-600">
      {/* Hero Section */}
      <section className="relative bg-gradient-to-br from-dark-500 via-dark-600 to-dark-700 text-white py-20 md:py-32 overflow-hidden">
        <div className="absolute inset-0 bg-hero-pattern opacity-10"></div>
        <div className="absolute inset-0 bg-gradient-to-r from-dark-900/20 to-transparent"></div>
        
        <div className="max-w-7xl mx-auto px-4 relative z-10">
          <div className="text-center mb-12">
            <Logo size="xl" variant="text" className="text-white mb-8 justify-center animate-fade-in" />
            <h1 className="text-4xl md:text-6xl font-extrabold leading-tight mb-6 animate-fade-in">
              {BRAND_CONFIG.tagline}
            </h1>
            <p className="text-lg md:text-xl mb-10 max-w-3xl mx-auto opacity-90 animate-slide-up">
              {BRAND_CONFIG.description}
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center animate-slide-up">
              <Button 
                asChild
                size="lg"
                className="group bg-primary-500 hover:bg-primary-600 text-white text-lg px-8 py-3 rounded-lg shadow-lg transform transition-all hover:scale-105 animate-bounce-gentle"
              >
                <Link to="/risk-assessment" className="inline-flex items-center">
                  <span>Try Risk Calculator Now</span>
                  <span className="ml-3 inline-flex h-7 w-7 items-center justify-center rounded-full bg-white/20 text-white ring-1 ring-white/30 transition-all group-hover:bg-white group-hover:text-primary-600 group-hover:translate-x-0.5">
                    <ArrowRight className="h-4 w-4" />
                  </span>
                </Link>
              </Button>
              <Button 
                asChild
                variant="outline" 
                size="lg"
                className="border-white text-white bg-transparent hover:bg-transparent hover:text-white dark:border-white dark:text-white dark:hover:bg-transparent dark:hover:text-white text-lg px-8 py-3 rounded-lg transition-colors"
              >
                <Link to="/about">
                  Learn More
                </Link>
              </Button>
            </div>
            <p className="text-white/80 text-sm mt-4 animate-slide-up delay-200">
              No account required • Free risk assessments • Powered by NVD & EPSS
            </p>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 bg-white dark:bg-dark-500">
        <div className="max-w-7xl mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
            <div className="animate-slide-up">
              <div className="text-3xl font-bold text-primary-500 mb-2">99.9%</div>
              <div className="text-sm text-gray-600 dark:text-gray-300">Accuracy Rate</div>
            </div>
            <div className="animate-slide-up delay-100">
              <div className="text-3xl font-bold text-primary-500 mb-2">24/7</div>
              <div className="text-sm text-gray-600 dark:text-gray-300">Real-time Monitoring</div>
            </div>
            <div className="animate-slide-up delay-200">
              <div className="text-3xl font-bold text-primary-500 mb-2">100%</div>
              <div className="text-sm text-gray-600 dark:text-gray-300">Transparent Scoring</div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Highlights Section */}
      <section className="py-20 bg-secondary-50 dark:bg-dark-600">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              Why Choose VulnRisk?
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
              Enterprise-grade vulnerability risk assessment with unparalleled transparency and accuracy
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up group bg-white dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-primary-100 dark:bg-primary-900/20 rounded-full mb-4 group-hover:bg-primary-200 dark:group-hover:bg-primary-900/30 transition-colors">
                  <Shield className="h-8 w-8 text-primary-600 dark:text-primary-400" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">Transparent Scoring</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                Understand every factor influencing your risk scores with our fully auditable and explainable methodology. 
                No black boxes, just clear, actionable insights.
              </CardContent>
            </Card>

            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up delay-100 group bg-white dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-accent-100 dark:bg-accent-900/20 rounded-full mb-4 group-hover:bg-accent-200 dark:group-hover:bg-accent-900/30 transition-colors">
                  <Brain className="h-8 w-8 text-accent-600 dark:text-accent-400" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">Powerful Insights</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                Leverage machine learning for predictive risk trends, anomaly detection, and intelligent recommendations 
                that adapt to your environment.
              </CardContent>
            </Card>

            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up delay-200 group bg-white dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-primary-100 dark:bg-primary-900/20 rounded-full mb-4 group-hover:bg-primary-200 dark:group-hover:bg-primary-900/30 transition-colors">
                  <Zap className="h-8 w-8 text-primary-600 dark:text-primary-400" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">Enterprise Scalability</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                Designed for high-performance batch processing and seamless integration into your existing 
                security workflows and CI/CD pipelines.
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Key Features Section */}
      <section className="py-20 bg-white dark:bg-dark-500">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              Comprehensive Risk Assessment
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
              From individual CVEs to enterprise-wide vulnerability management
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="text-center p-6 rounded-lg bg-gradient-to-br from-primary-50 to-primary-100 dark:from-primary-900/20 dark:to-primary-900/10 animate-slide-up">
              <Target className="h-12 w-12 text-primary-600 dark:text-primary-400 mx-auto mb-4" />
              <h3 className="font-semibold text-gray-800 dark:text-white mb-2">Individual CVE Analysis</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">Detailed risk scoring for single vulnerabilities</p>
            </div>

            <div className="text-center p-6 rounded-lg bg-gradient-to-br from-success-50 to-success-100 dark:from-success-900/20 dark:to-success-900/10 animate-slide-up delay-100">
              <BarChart3 className="h-12 w-12 text-success-600 dark:text-success-400 mx-auto mb-4" />
              <h3 className="font-semibold text-gray-800 dark:text-white mb-2">Batch Processing</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">Process thousands of CVEs simultaneously</p>
            </div>

            <div className="text-center p-6 rounded-lg bg-gradient-to-br from-warning-50 to-warning-100 dark:from-warning-900/20 dark:to-warning-900/10 animate-slide-up delay-200">
              <Eye className="h-12 w-12 text-warning-600 dark:text-warning-400 mx-auto mb-4" />
              <h3 className="font-semibold text-gray-800 dark:text-white mb-2">Real-time Monitoring</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">Continuous vulnerability tracking</p>
            </div>

            <div className="text-center p-6 rounded-lg bg-gradient-to-br from-accent-50 to-accent-100 dark:from-accent-900/20 dark:to-accent-900/10 animate-slide-up delay-300">
              <Lock className="h-12 w-12 text-accent-600 dark:text-accent-400 mx-auto mb-4" />
              <h3 className="font-semibold text-gray-800 dark:text-white mb-2">Encrypted</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">Military Grade Encryption</p>
            </div>
          </div>
        </div>
      </section>

      {/* Risk Assessment Frameworks */}
      <section className="py-20 bg-white dark:bg-dark-600">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              Risk Assessment Frameworks
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-200 max-w-3xl mx-auto">
              Three mathematically validated approaches to vulnerability risk scoring. 
              Each framework uses transparent formulas that you can understand and audit.
            </p>
          </div>

          <div className="space-y-12">
            {/* Enhanced Contextual Framework */}
            <Card className="p-8 border-2 border-blue-200 dark:border-blue-700 bg-blue-50 dark:bg-blue-900/20 dark:ring-1 dark:ring-blue-500/40 dark:shadow-[0_0_0_1px_rgba(59,130,246,0.25)]">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Enhanced Contextual</h3>
                  <p className="text-gray-600 dark:text-gray-300 text-lg">
                    Fast, business-aligned risk scoring with real vulnerability data
                  </p>
                </div>
              </div>
              
              <div className="bg-white dark:bg-dark-500 p-6 rounded-lg mb-6 dark:border dark:border-blue-800/40 dark:shadow-inner">
                <h4 className="font-bold text-gray-800 dark:text-white mb-3">Mathematical Formula:</h4>
                <code className="block bg-gray-100 dark:bg-dark-600 p-4 rounded text-sm font-mono text-gray-900 dark:text-gray-100">
                  Risk_Score = (Base_Risk × Reachability_Multiplier) × 2
                </code>
                <div className="mt-4 space-y-2 text-sm text-gray-700 dark:text-gray-300">
                  <div><strong>Base_Risk =</strong> (CVSS × 0.4) + (Asset_Criticality × 0.4) + (EPSS × 100 × 0.2)</div>
                  <div><strong>Reachability =</strong> Network_Exposure × Attack_Path_Complexity (from real CVSS vector)</div>
                  <div><strong>Data Sources =</strong> Live NVD API, FIRST.org EPSS, CISA KEV catalog</div>
                </div>
              </div>

            </Card>

            {/* Mitigation Contextual Framework */}
            <Card className="p-8 border-2 border-green-200 dark:border-green-700 bg-green-50 dark:bg-green-900/20">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Mitigation Contextual</h3>
                  <p className="text-gray-600 dark:text-gray-300 text-lg">
                    CVE-aware security controls with intelligent context determination
                  </p>
                </div>
              </div>
              
              <div className="bg-white dark:bg-dark-500 p-6 rounded-lg mb-6">
                <h4 className="font-bold text-gray-800 dark:text-white mb-3">Mathematical Formula:</h4>
                <code className="block bg-gray-100 dark:bg-dark-600 p-4 rounded text-sm font-mono text-gray-900 dark:text-gray-100">
                  Risk_Score = (Base_Risk × Reachability_Multiplier × (1 - Mitigation_Factor)) × 2
                </code>
                <div className="mt-4 space-y-2 text-sm text-gray-700 dark:text-gray-300">
                  <div><strong>Base_Risk =</strong> (CVSS × 0.4) + (Asset_Criticality × 0.4) + (EPSS × 100 × 0.2)</div>
                  <div><strong>Reachability =</strong> Network_Exposure × Attack_Path_Complexity (from real CVSS vector)</div>
                  <div><strong>Mitigation =</strong> User-specified controls with intelligent context (up to 90% reduction)</div>
                  <div><strong>Intelligence =</strong> Real CVE age, CISA KEV status, exploit references, threat factors</div>
                </div>
              </div>

            </Card>

            {/* Risk Based Framework */}
            <Card className="p-8 border-2 border-purple-200 dark:border-purple-700 bg-purple-50 dark:bg-purple-900/20">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Risk Based</h3>
                  <p className="text-gray-600 dark:text-gray-300 text-lg">
                    Complete Master Formula with all context, threat, and temporal multipliers
                  </p>
                </div>
              </div>
              
              <div className="bg-white dark:bg-dark-500 p-6 rounded-lg mb-6">
                <h4 className="font-bold text-gray-800 dark:text-white mb-3">Mathematical Formula:</h4>
                <code className="block bg-gray-100 dark:bg-dark-600 p-4 rounded text-sm font-mono text-gray-900 dark:text-gray-100">
                  Final_Risk_Score = (Base_Risk × Context_Multipliers × Threat_Multipliers × Mitigation_Divisors) × 2
                </code>
                <div className="mt-4 space-y-2 text-sm text-gray-700 dark:text-gray-300">
                  <div><strong>Base_Risk =</strong> (Technical_Severity × 0.4) + (Business_Impact × 0.4) + (Exploit_Likelihood × 0.2)</div>
                  <div><strong>Context_Multipliers =</strong> Reachability × Detectability × Prevalence (from real CVE/EPSS data)</div>
                  <div><strong>Threat_Multipliers =</strong> Threat_Actor × Temporal (CISA KEV, age, patch status)</div>
                  <div><strong>Mitigation_Divisors =</strong> (1 - Complete_Mitigation_Factor) with context-based priority floors</div>
                  <div><strong>Intelligence =</strong> Real NVD publication dates, CISA KEV catalog, EPSS percentiles, exploit detection</div>
                </div>
              </div>

            </Card>

            {/* FedRAMP VDR Standard */}
            <Card className="p-8 border-2 border-green-200 dark:border-green-700 bg-green-50 dark:bg-green-900/20">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">FedRAMP VDR Standard</h3>
                  <p className="text-gray-600 dark:text-gray-300 text-lg">
                    N1–N5 federal impact classification with LEV/IRV assessment and exact timeline enforcement
                  </p>
                </div>
                <Badge className="bg-green-100 text-green-800">Federal</Badge>
              </div>
              
              <div className="bg-white dark:bg-dark-500 p-6 rounded-lg mb-6">
                <h4 className="font-bold text-gray-800 dark:text-white mb-3">Mathematical Framework:</h4>
                <code className="block bg-gray-100 dark:bg-dark-600 p-4 rounded text-sm font-mono text-gray-900 dark:text-gray-100">
                  Timeline_Days = f( Impact_Rating(N1–N5), LEV, IRV, Authorization_Level )
                </code>
                <div className="mt-4 space-y-2 text-sm text-gray-700 dark:text-gray-300">
                  <div><strong>Impact_Rating:</strong> N1–N5 per FRR‑VDR‑09 (federal data exposure, degradation/downtime, users)</div>
                  <div><strong>LEV:</strong> Likely Exploitable per FRD‑ALL‑23 (not fully mitigated + reachable + likely exploitation)</div>
                  <div><strong>IRV:</strong> Internet‑Reachable per FRD‑ALL‑24 (payload‑triggered, not just open ports)</div>
                  <div><strong>Context Factors:</strong> FRR‑VDR‑10 (criticality, reachability, exploitability, detectability, prevalence, privilege, proximate vulns, known threats)</div>
                  <div><strong>Timelines:</strong> Exact LEV+IRV / LEV+NIRV / NLEV (NLEV = Not Likely Exploitable) tables for Low/Moderate/High authorization</div>
                  <div><strong>Reporting:</strong> FRR‑VDR‑RP‑05 machine‑readable fields & incident response triggers (e.g., KEV + IRV may initiate IR)</div>
                  <div><strong>Example (Moderate):</strong> N3 with LEV+NIRV → 32 days; N4 with LEV+IRV → 4 days. High/Low levels adjust these thresholds.</div>
                </div>
              </div>

            </Card>
          </div>

          {/* Framework Selection Guide */}
          <div className="mt-16 bg-gradient-to-r from-gray-50 to-gray-100 dark:from-dark-500 dark:to-dark-400 rounded-2xl p-8">
            <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-6 text-center">
              Which Framework Should You Choose?
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="bg-blue-100 dark:bg-blue-900 rounded-full p-3 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                  <Zap className="h-8 w-8 text-blue-600 dark:text-blue-400" />
                </div>
                <h4 className="font-semibold text-gray-800 dark:text-white mb-2">Need Speed?</h4>
                <p className="text-sm text-gray-600 dark:text-gray-300">Choose <strong>Enhanced Contextual</strong> for fast, business-focused assessments</p>
              </div>
              <div className="text-center">
                <div className="bg-green-100 dark:bg-green-900 rounded-full p-3 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                  <Shield className="h-8 w-8 text-green-600 dark:text-green-400" />
                </div>
                <h4 className="font-semibold text-gray-800 dark:text-white mb-2">Security Focus?</h4>
                <p className="text-sm text-gray-600 dark:text-gray-300">Choose <strong>Mitigation Contextual</strong> for intelligent control optimization</p>
              </div>
              <div className="text-center">
                <div className="bg-purple-100 dark:bg-purple-900 rounded-full p-3 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                  <Award className="h-8 w-8 text-purple-600 dark:text-purple-400" />
                </div>
                <h4 className="font-semibold text-gray-800 dark:text-white mb-2">Need Compliance?</h4>
                <p className="text-sm text-gray-600 dark:text-gray-300">Choose <strong>Risk Based</strong> for complete regulatory compliance</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="bg-gradient-to-r from-dark-500 to-dark-600 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            Ready to Transform Your Vulnerability Management?
          </h2>
          <p className="text-lg mb-8 opacity-90 max-w-2xl mx-auto">
            Get started with VulnRisk today and gain unparalleled clarity into your security posture. 
            Join thousands of security professionals who trust our platform.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <Button 
              asChild
              size="lg"
              className="bg-primary-500 hover:bg-primary-600 text-white text-lg px-8 py-3 rounded-lg shadow-lg transform transition-all hover:scale-105"
            >
              <Link to="/risk-assessment">
                Start Free Assessment
                <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-dark-500 text-white py-12">
        <div className="max-w-7xl mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div className="col-span-1 md:col-span-2">
              <Logo size="lg" variant="text" className="text-white mb-4" />
              <p className="text-gray-300 mb-4 max-w-md">
                Enterprise-grade vulnerability risk assessment with full transparency and explainable methodology. 
                Trusted by security professionals worldwide.
              </p>
              <div className="flex space-x-4">
                <a href="#" aria-label="View source branches" title="View source branches" className="text-gray-400 hover:text-white transition-colors">
                  <GitBranch className="h-5 w-5" />
                </a>
                <a href="#" aria-label="View activity" title="View activity" className="text-gray-400 hover:text-white transition-colors">
                  <Activity className="h-5 w-5" />
                </a>
              </div>
            </div>
            
            <div>
              <h3 className="font-semibold mb-4">Product</h3>
              <ul className="space-y-2 text-gray-300">
                <li><Link to="/risk-assessment" className="hover:text-white transition-colors">Risk Calculator</Link></li>
                <li><Link to="/analytics" className="hover:text-white transition-colors">Analytics</Link></li>
                <li><Link to="/batch" className="hover:text-white transition-colors">Batch Processing</Link></li>
                <li><Link to="/api-key-management" className="hover:text-white transition-colors">API Keys</Link></li>
              </ul>
            </div>
            
            <div>
              <h3 className="font-semibold mb-4">Company</h3>
              <ul className="space-y-2 text-gray-300">
                <li><Link to="/about" className="hover:text-white transition-colors">About</Link></li>
                <li><a href="#" className="hover:text-white transition-colors">Documentation</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Support</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Contact</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-gray-700 mt-8 pt-8 text-center text-gray-400">
            <p>&copy; {new Date().getFullYear()} VulnRisk. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default HomePage; 