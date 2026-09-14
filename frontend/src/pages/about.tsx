import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
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
  Activity,
  Heart,
  Lightbulb,
  Rocket,
  Globe2,
  ShieldCheck,
  Zap as ZapIcon,
  BarChart,
  FileCode,
  GitCommit,
  Package,
  Server,
  Monitor,
  AlertTriangle,
  Clock,
  RefreshCw
} from 'lucide-react';

const AboutPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-secondary-50 to-primary-50 dark:from-dark-500 dark:to-dark-600">
      {/* Hero Section */}
      <section className="relative bg-gradient-to-br from-primary-600 via-primary-700 to-primary-800 text-white py-20 md:py-32 overflow-hidden">
        <div className="absolute inset-0 bg-hero-pattern opacity-10"></div>
        <div className="absolute inset-0 bg-gradient-to-r from-primary-900/20 to-transparent"></div>
        
        <div className="max-w-7xl mx-auto px-4 relative z-10">
          <div className="text-center">
            <Logo size="xl" variant="text" className="text-white mb-8 justify-center animate-fade-in" />
            <h1 className="text-4xl md:text-6xl font-extrabold leading-tight mb-6 animate-fade-in">
              About VulnRisk
            </h1>
            <p className="text-lg md:text-xl mb-10 max-w-3xl mx-auto opacity-90 animate-slide-up">
              Revolutionizing vulnerability risk assessment with transparency, accuracy, and enterprise-grade capabilities
            </p>
          </div>
        </div>
      </section>

      

      {/* Mission Section */}
      <section className="py-20 bg-white dark:bg-dark-500">
        <div className="max-w-7xl mx-auto px-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div className="animate-slide-up">
              <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-6">
                Our Mission
              </h2>
              <p className="text-lg text-gray-600 dark:text-gray-300 mb-6">
                VulnRisk was born from a simple yet powerful idea: vulnerability risk assessment should be 
                transparent, accurate, and accessible to everyone. We believe that security professionals 
                deserve tools that not only identify risks but explain them in clear, actionable terms.
              </p>
              <p className="text-lg text-gray-600 dark:text-gray-300 mb-8">
                Our platform combines cutting-edge AI with traditional security methodologies to provide 
                comprehensive risk assessments that organizations can trust and understand.
              </p>
              <div className="flex flex-wrap gap-4">
                <Badge variant="secondary">
                  <Shield className="h-4 w-4 mr-2" />
                  Security First
                </Badge>
                <Badge variant="secondary">
                  <Eye className="h-4 w-4 mr-2" />
                  Transparent
                </Badge>
                <Badge variant="secondary">
                  <Brain className="h-4 w-4 mr-2" />
                  Intelligent
                </Badge>
              </div>
            </div>
            <div className="animate-slide-up delay-100">
              <div className="bg-gradient-to-br from-primary-50 to-primary-100 dark:from-primary-900/20 dark:to-primary-900/10 rounded-2xl p-8">
                <div className="grid grid-cols-2 gap-6">
                  <div className="text-center">
                    <div className="bg-white rounded-full p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                      <Target className="h-8 w-8 text-primary-600" />
                    </div>
                    <h3 className="font-semibold text-gray-800 mb-2">Precision</h3>
                    <p className="text-sm text-gray-600">99.9% accuracy rate</p>
                  </div>
                  <div className="text-center">
                    <div className="bg-white rounded-full p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                      <Zap className="h-8 w-8 text-primary-600" />
                    </div>
                    <h3 className="font-semibold text-gray-800 mb-2">Batch</h3>
                    <p className="text-sm text-gray-600">Multiple CVEs at once</p>
                  </div>
                  <div className="text-center">
                    <div className="bg-white rounded-full p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                      <ShieldCheck className="h-8 w-8 text-primary-600" />
                    </div>
                    <h3 className="font-semibold text-gray-800 mb-2">Security</h3>
                    <p className="text-sm text-gray-600">Enterprise-grade</p>
                  </div>
                  <div className="text-center">
                    <div className="bg-white rounded-full p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                      <Globe2 className="h-8 w-8 text-primary-600" />
                    </div>
                    <h3 className="font-semibold text-gray-800 mb-2">Global</h3>
                    <p className="text-sm text-gray-600">24/7 availability</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Risk Assessment Frameworks */}
      <section className="py-20 bg-white dark:bg-dark-500">
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
            <Card className="p-8 border-2 border-blue-200 bg-blue-50 dark:bg-dark-500 dark:border-blue-900/40">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Enhanced Contextual</h3>
                  <p className="text-gray-600 dark:text-gray-300 text-lg">
                    Fast, business-aligned risk scoring with real vulnerability data
                  </p>
                </div>
                <Badge className="bg-blue-100 text-blue-800">Live NVD/EPSS</Badge>
              </div>
              
              <div className="bg-white dark:bg-dark-600 p-6 rounded-lg mb-6">
                <h4 className="font-bold text-gray-800 dark:text-white mb-3">Mathematical Formula:</h4>
                <code className="block bg-gray-100 dark:bg-dark-500 p-4 rounded text-sm font-mono text-gray-900 dark:text-gray-100">
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
            <Card className="p-8 border-2 border-green-200 bg-green-50 dark:bg-dark-500 dark:border-green-900/40">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Mitigation Contextual</h3>
                  <p className="text-gray-600 dark:text-gray-300 text-lg">
                    CVE-aware security controls with intelligent context determination
                  </p>
                </div>
                <Badge className="bg-green-100 text-green-800">Real CVE Data</Badge>
              </div>
              
              <div className="bg-white dark:bg-dark-600 p-6 rounded-lg mb-6">
                <h4 className="font-bold text-gray-800 dark:text-white mb-3">Mathematical Formula:</h4>
                <code className="block bg-gray-100 dark:bg-dark-500 p-4 rounded text-sm font-mono text-gray-900 dark:text-gray-100">
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
            <Card className="p-8 border-2 border-purple-200 bg-purple-50 dark:bg-dark-500 dark:border-purple-900/40">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Risk Based</h3>
                  <p className="text-gray-600 dark:text-gray-300 text-lg">
                    Complete Master Formula with all context, threat, and temporal multipliers
                  </p>
                </div>
                <Badge className="bg-purple-100 text-purple-800">15+ Real Factors</Badge>
              </div>
              
              <div className="bg-white dark:bg-dark-600 p-6 rounded-lg mb-6">
                <h4 className="font-bold text-gray-800 dark:text-white mb-3">Mathematical Formula:</h4>
                <code className="block bg-gray-100 dark:bg-dark-500 p-4 rounded text-sm font-mono text-gray-900 dark:text-gray-100">
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

            {/* FedRAMP VDR Framework */}
            <Card className="p-8 border-2 border-red-200 bg-red-50">
              <div className="flex items-start justify-between mb-6">
                <div>
            <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">FedRAMP VDR Standard</h3>
            <p className="text-gray-600 dark:text-gray-300 text-lg">
                    N1–N5 federal impact classification with LEV/IRV assessment and exact timeline enforcement
                  </p>
                </div>
                <Badge className="bg-red-100 text-red-800">Federal</Badge>
              </div>

              <div className="bg-white dark:bg-dark-600 p-6 rounded-lg mb-6">
                <h4 className="font-bold text-gray-800 dark:text-white mb-3">Mathematical Framework:</h4>
                <code className="block bg-gray-100 dark:bg-dark-500 p-4 rounded text-sm font-mono text-gray-900 dark:text-gray-100">
                  Timeline_Days = f( Impact_Rating(N1–N5), LEV, IRV, Authorization_Level )
                </code>
                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-gray-700 dark:text-gray-300">
                  <div className="space-y-1">
                    <div><strong>Impact_Rating:</strong> N1–N5 per FRR‑VDR‑09 (federal data exposure, degradation/downtime, users)</div>
                    <div><strong>LEV:</strong> Likely Exploitable per FRD‑ALL‑23 (not fully mitigated + reachable + likely exploitation)</div>
                    <div><strong>IRV:</strong> Internet‑Reachable per FRD‑ALL‑24 (payload‑triggered, not just open ports)</div>
                  </div>
                  <div className="space-y-1">
                    <div><strong>Context Factors:</strong> FRR‑VDR‑10 (criticality, reachability, exploitability, detectability, prevalence, privilege, proximate vulns, known threats)</div>
                    <div><strong>Timelines:</strong> Exact LEV+IRV / LEV+NIRV / NLEV (NLEV = Not Likely Exploitable) tables for Low/Moderate/High authorization</div>
                    <div><strong>Reporting:</strong> FRR‑VDR‑RP‑05 machine‑readable fields & incident response triggers (e.g., KEV + IRV may initiate IR)</div>
                  </div>
                </div>
              </div>

              <div className="text-xs text-gray-600 dark:text-gray-300">
                Example (Moderate): N3 with LEV+NIRV → 32 days; N4 with LEV+IRV → 4 days. High/Low levels adjust these thresholds.
              </div>
            </Card>

          </div>

          {/* Framework Selection Guide */}
          <div className="mt-16 bg-gradient-to-r from-gray-50 to-gray-100 dark:from-dark-500 dark:to-dark-400 rounded-2xl p-8">
            <h3 className="text-2xl font-bold text-gray-900 mb-6 text-center">
              Which Framework Should You Choose?
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="bg-blue-100 rounded-full p-3 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                  <Zap className="h-8 w-8 text-blue-600" />
                </div>
                <h4 className="font-semibold text-gray-800 mb-2">Need Speed?</h4>
                <p className="text-sm text-gray-600">Choose <strong>Enhanced Contextual</strong> for fast, business-focused assessments</p>
              </div>
              <div className="text-center">
                <div className="bg-green-100 rounded-full p-3 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                  <Shield className="h-8 w-8 text-green-600" />
                </div>
                <h4 className="font-semibold text-gray-800 mb-2">Security Focus?</h4>
                <p className="text-sm text-gray-600">Choose <strong>Mitigation Contextual</strong> for intelligent control optimization</p>
              </div>
              <div className="text-center">
                <div className="bg-purple-100 rounded-full p-3 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                  <Award className="h-8 w-8 text-purple-600" />
                </div>
                <h4 className="font-semibold text-gray-800 mb-2">Need Compliance?</h4>
                <p className="text-sm text-gray-600">Choose <strong>Risk Based</strong> for complete regulatory compliance</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Risk Score Interpretation Guide */}
      <section className="py-20 bg-gradient-to-br from-purple-50 to-pink-50 dark:from-dark-500 dark:to-dark-600">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              Risk Score Interpretation Guide
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-200 max-w-3xl mx-auto">
              Understanding what your risk scores mean in real-world terms. 
              Our extended scale provides granular risk discrimination for sophisticated threat modeling.
            </p>
          </div>

          <div className="max-w-5xl mx-auto">
            <Card className="p-8 shadow-lg">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b-2 border-purple-200">
                      <th className="text-left p-3 font-semibold text-gray-800">Score Range</th>
                      <th className="text-left p-3 font-semibold text-gray-800">Priority</th>
                      <th className="text-left p-3 font-semibold text-gray-800">Timeline</th>
                      <th className="text-left p-3 font-semibold text-gray-800">Real-World Examples</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-gray-200 bg-red-50">
                      <td className="p-3 font-mono text-red-800 font-semibold">≥ 90</td>
                      <td className="p-3">
                        <Badge className="bg-red-100 text-red-800 border-red-200">CRITICAL</Badge>
                      </td>
                      <td className="p-3 text-gray-700 font-medium">7 days (base)</td>
                      <td className="p-3 text-gray-700">Emergency response window; immediate risk to business</td>
                    </tr>
                    <tr className="border-b border-gray-200 bg-orange-50">
                      <td className="p-3 font-mono text-orange-800 font-semibold">70–89</td>
                      <td className="p-3">
                        <Badge className="bg-orange-100 text-orange-800 border-orange-200">HIGH</Badge>
                      </td>
                      <td className="p-3 text-gray-700 font-medium">30 days (base)</td>
                      <td className="p-3 text-gray-700">Serious threats; prioritize this sprint/month</td>
                    </tr>
                    <tr className="border-b border-gray-200 bg-yellow-50">
                      <td className="p-3 font-mono text-yellow-800 font-semibold">40–69</td>
                      <td className="p-3">
                        <Badge className="bg-yellow-100 text-yellow-800 border-yellow-200">MEDIUM</Badge>
                      </td>
                      <td className="p-3 text-gray-700 font-medium">60 days (base)</td>
                      <td className="p-3 text-gray-700">Significant risk; plan within quarter</td>
                    </tr>
                    <tr className="border-b border-gray-200 bg-blue-50">
                      <td className="p-3 font-mono text-blue-800 font-semibold">20–39</td>
                      <td className="p-3">
                        <Badge className="bg-blue-100 text-blue-800 border-blue-200">LOW</Badge>
                      </td>
                      <td className="p-3 text-gray-700 font-medium">120 days (base)</td>
                      <td className="p-3 text-gray-700">Lower priority; standard maintenance</td>
                    </tr>
                    <tr className="border-b border-gray-200 bg-gray-50">
                      <td className="p-3 font-mono text-gray-600 font-semibold">&lt; 20</td>
                      <td className="p-3">
                        <Badge className="bg-gray-100 text-gray-800 border-gray-200">INFORMATIONAL</Badge>
                      </td>
                      <td className="p-3 text-gray-700 font-medium">Next maintenance window</td>
                      <td className="p-3 text-gray-700">Track/monitor; negligible business impact</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div className="mt-8">
                <div className="bg-purple-50 p-6 rounded-lg max-w-3xl mx-auto">
                  <h4 className="font-semibold text-gray-800 mb-3">📊 Timeline Accelerators (apply to base timeline)</h4>
                  <ul className="text-sm text-gray-600 space-y-2">
                    <li>• <strong>CISA KEV:</strong> cap at 14 days</li>
                    <li>• <strong>Active exploitation:</strong> halve timeline (minimum 3 days)</li>
                    <li>• <strong>High asset criticality:</strong> ~30% faster (minimum 5 days)</li>
                    <li>• <strong>Internet‑reachable exposure:</strong> additional acceleration</li>
                    <li>• Accelerators adjust days; labels don’t change unless the score changes</li>
                  </ul>
                </div>
              </div>
            </Card>
          </div>
        </div>
      </section>

      {/* FedRAMP VDR Standard (placed after Risk Score Interpretation Guide) */}
      <section className="py-20 bg-gradient-to-br from-green-50 to-emerald-50 dark:from-dark-500 dark:to-dark-600">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              FedRAMP VDR Standard (N1–N5)
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-200 max-w-3xl mx-auto">
              The FedRAMP VDR framework does not use numeric risk scores. It assigns an impact rating (N1–N5) and
              derives remediation timelines based on Likely Exploitable (LEV) and Internet‑Reachable (IRV) status and
              the authorization level (Low, Moderate, High). Below reflects the Moderate authorization matrix used in the app.
            </p>
          </div>

          <div className="max-w-5xl mx-auto">
            <Card className="p-8 shadow-lg dark:bg-dark-500">
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">Moderate Authorization Timelines</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b-2 border-green-200">
                      <th className="text-left p-3 font-semibold text-gray-800 dark:text-gray-200">Impact</th>
                      <th className="text-left p-3 font-semibold text-gray-800 dark:text-gray-200">LEV + IRV</th>
                      <th className="text-left p-3 font-semibold text-gray-800 dark:text-gray-200">LEV + NIRV</th>
                      <th className="text-left p-3 font-semibold text-gray-800 dark:text-gray-200">NLEV</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-gray-200">
                      <td className="p-3 font-mono text-red-800 font-semibold">N5</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">2 days</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">4 days</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">16 days</td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="p-3 font-mono text-red-700 font-semibold">N4</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">4 days</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">8 days</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">64 days</td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="p-3 font-mono text-orange-700 font-semibold">N3</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">16 days</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">32 days</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">128 days</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-mono text-yellow-700 font-semibold">N2</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">48 days</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">128 days</td>
                      <td className="p-3 text-gray-700 dark:text-gray-300 font-medium">192 days</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div className="mt-8 bg-white p-6 rounded-lg border border-green-200">
                <h4 className="font-semibold text-gray-800 mb-3">Assessment Signals</h4>
                <ul className="text-sm text-gray-700 space-y-2">
                  <li>• Impact rating: <strong>N1–N5</strong> based on federal data exposure, service degradation, downtime, affected users</li>
                  <li>• LEV (Likely Exploitable): based on mitigation effectiveness, reachability, and exploitation likelihood (e.g., EPSS, KEV)</li>
                  <li>• IRV (Internet‑Reachable): payload‑triggered reachability, not just network accessibility</li>
                </ul>
              </div>

              <div className="mt-4 bg-white p-6 rounded-lg border border-green-200">
                <h4 className="font-semibold text-gray-800 mb-3">Incident Response Guidance</h4>
                <ul className="text-sm text-gray-700 space-y-2">
                  <li>• Treat <strong>N4/N5 with LEV+IRV</strong> as a security incident until partially mitigated</li>
                  <li>• KEV items should be prioritized according to CISA requirements and provider policy</li>
                </ul>
              </div>
            </Card>
          </div>
        </div>
      </section>

      {/* Features Overview */}
      <section className="py-20 bg-gray-50 dark:bg-dark-600">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              Comprehensive Feature Set
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
              Everything you need for enterprise vulnerability risk management
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-primary-100 rounded-full mb-4">
                  <Target className="h-8 w-8 text-primary-600" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">Individual CVE Analysis</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                <p className="mb-4">Detailed risk scoring for single vulnerabilities with comprehensive breakdowns</p>
                <ul className="text-sm space-y-1 text-left">
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />CVSS Score Integration</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />EPSS Exploitability</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Business Context</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up delay-100 dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-success-100 rounded-full mb-4">
                  <BarChart3 className="h-8 w-8 text-success-600" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">Batch Processing</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                <p className="mb-4">Process thousands of CVEs simultaneously with high-performance processing</p>
                <ul className="text-sm space-y-1 text-left">
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />CSV Upload Support</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Parallel Processing</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Progress Tracking</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up delay-200 dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-warning-100 rounded-full mb-4">
                  <Eye className="h-8 w-8 text-warning-600" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">Real-time Monitoring</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                <p className="mb-4">Continuous vulnerability tracking with automated alerts and updates</p>
                <ul className="text-sm space-y-1 text-left">
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Live Updates</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Alert System</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Trend Analysis</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up delay-300 dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-accent-100 rounded-full mb-4">
                  <Lock className="h-8 w-8 text-accent-600" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">Encrypted</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                <p className="mb-4">Military Grade Encryption</p>
                <ul className="text-sm space-y-1 text-left">
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />RFC-0012 Support</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Audit Trails</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Compliance Reports</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up delay-400 dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-purple-100 rounded-full mb-4">
                  <Brain className="h-8 w-8 text-purple-600" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">Powerful Insights</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                <p className="mb-4">Machine learning for predictive analysis and intelligent recommendations</p>
                <ul className="text-sm space-y-1 text-left">
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Risk Prediction</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Anomaly Detection</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Smart Recommendations</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="p-6 shadow-soft hover:shadow-medium transition-all duration-300 animate-slide-up delay-500 dark:bg-dark-500">
              <CardHeader className="flex flex-col items-center text-center">
                <div className="p-3 bg-indigo-100 rounded-full mb-4">
                  <Zap className="h-8 w-8 text-indigo-600" />
                </div>
                <CardTitle className="text-xl font-semibold text-gray-800 dark:text-white">API Integration</CardTitle>
              </CardHeader>
              <CardContent className="text-gray-600 dark:text-gray-300 text-center">
                <p className="mb-4">Seamless integration with existing security tools and workflows</p>
                <ul className="text-sm space-y-1 text-left">
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />RESTful APIs</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />Webhook Support</li>
                  <li className="flex items-center"><CheckCircle className="h-4 w-4 text-success-500 mr-2" />CI/CD Integration</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>


      {/* Development Philosophy */}
      <section className="py-20 bg-gray-50 dark:bg-dark-600">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Our Development Philosophy
            </h2>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Guiding principles that drive our innovation and development
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="text-center p-6">
              <div className="bg-white rounded-full p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <Heart className="h-8 w-8 text-accent-600" />
              </div>
              <h3 className="text-xl font-semibold text-gray-800 mb-3">User-Centric Design</h3>
              <p className="text-gray-600">
                Every feature is designed with security professionals in mind. We prioritize usability, 
                clarity, and actionable insights over complex interfaces.
              </p>
            </div>

            <div className="text-center p-6">
              <div className="bg-white rounded-full p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <Lightbulb className="h-8 w-8 text-warning-600" />
              </div>
              <h3 className="text-xl font-semibold text-gray-800 mb-3">Continuous Innovation</h3>
              <p className="text-gray-600">
                We constantly evolve our platform based on the latest security research, user feedback, 
                and emerging threats to stay ahead of the curve.
              </p>
            </div>

            <div className="text-center p-6">
              <div className="bg-white rounded-full p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <Rocket className="h-8 w-8 text-success-600" />
              </div>
              <h3 className="text-xl font-semibold text-gray-800 mb-3">Performance First</h3>
              <p className="text-gray-600">
                Speed and reliability are non-negotiable. Our platform is built to handle enterprise-scale 
                workloads with sub-second response times.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="bg-gradient-to-r from-primary-600 to-primary-700 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            Ready to Get Started?
          </h2>
          <p className="text-lg mb-8 opacity-90 max-w-2xl mx-auto">
            Join thousands of security professionals who trust VulnRisk for their vulnerability management needs. 
            Start your free assessment today.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <Button 
              asChild
              size="lg"
              className="bg-white text-primary-700 hover:bg-gray-100 text-lg px-8 py-3 rounded-lg shadow-lg transform transition-all hover:scale-105"
            >
              <Link to="/risk-assessment">
                Start Free Assessment
                <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
            </Button>
            <Button
              size="lg"
              className="bg-white/10 hover:bg-white/20 text-white text-lg px-8 py-3 rounded-lg border border-white/30 backdrop-blur-sm"
              onClick={() => {
                const base = 'https://animogovcon.com/industry';
                const url = `${base}?source=vulnrisk&subject=${encodeURIComponent('VulnRisk Enterprise License Inquiry')}`;
                const clipboardText = 'VulnRisk Enterprise License Inquiry';
                if (navigator.clipboard?.writeText) {
                  navigator.clipboard.writeText(clipboardText).catch(() => {});
                }
                window.open(url, '_blank', 'noopener,noreferrer');
              }}
            >
              Contact Sales
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
};

export default AboutPage; 