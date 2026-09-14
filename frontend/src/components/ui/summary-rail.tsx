import { Button } from './button';
import { Card, CardContent, CardHeader, CardTitle } from './card';
import { Badge } from './badge';
import { AlertTriangle, CheckCircle2, Calculator, Target, Settings } from 'lucide-react';

type SummaryRailProps = {
  selectedFramework: string;
  cveId: string;
  assetCriticality?: number;
  authorizationLevel?: string;
  assetCriticalityRating?: string;
  autoPopulatedData: {
    epss?: number;
    cvss?: number;
    kev?: boolean;
    patchAvailable?: boolean;
  };
  impactData: {
    mitigation_level?: string;
    mitigation_effectiveness?: number;
    federal_data_exposure?: number;
    affected_users?: number;
  };
  environmentData: {
    reachability_paths?: string[];
    threat_intel_tags?: string[];
    internet_reachable?: boolean;
  };
  controlsSummary?: {
    preventive?: number;
    detective?: number;
    response?: number;
  };
  warnings: string[];
  onCalculate: () => void;
  isLoading: boolean;
  canCalculate: boolean;
};

export function SummaryRail({
  selectedFramework,
  cveId,
  assetCriticality,
  authorizationLevel,
  assetCriticalityRating,
  autoPopulatedData,
  impactData,
  environmentData,
  controlsSummary,
  warnings,
  onCalculate,
  isLoading,
  canCalculate
}: SummaryRailProps) {
  return (
    <div className="w-full space-y-2">
      {/* Assessment Summary - Clean and professional */}
      <Card className="border border-gray-200 bg-white shadow-lg dark:border-gray-700 dark:bg-dark-500">
        <div className="mb-1 border-b border-gray-200 pb-2 bg-gray-50 rounded-t-lg dark:border-gray-700 dark:bg-dark-600">
          <CardTitle className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <Target className="h-4 w-4" />
            Assessment Summary
          </CardTitle>
        </div>
        <CardContent className="space-y-1 pt-1">
          <div>
            <div className="text-xs font-medium text-gray-700">Framework</div>
            <Badge variant="outline" className="mt-1 text-blue-700 border-blue-300 bg-white text-xs">
              {selectedFramework === 'fedramp-vdr' ? 'FedRAMP VDR' :
               selectedFramework === 'mitigation-contextual' ? 'Mitigation Contextual' :
               selectedFramework === 'risk-based' ? 'Risk Based' : 'Enhanced Contextual'}
            </Badge>
          </div>

          {cveId && (
            <div>
              <div className="text-xs font-medium text-gray-700">CVE ID</div>
              <div className="text-xs font-mono bg-white px-2 py-1 rounded mt-1 border border-gray-200 font-semibold text-gray-900">{cveId}</div>
            </div>
          )}

          {selectedFramework === 'fedramp-vdr' ? (
            <>
              {authorizationLevel && (
                <div>
                  <div className="text-xs font-medium text-gray-700">Authorization Level</div>
                  <div className="text-xs capitalize mt-1 font-semibold bg-white px-2 py-1 rounded border border-gray-200">{authorizationLevel}</div>
                </div>
              )}
              {assetCriticalityRating && (
                <div>
                  <div className="text-xs font-medium text-gray-700">Asset Criticality</div>
                  <div className="text-xs capitalize mt-1 font-semibold bg-white px-2 py-1 rounded border border-gray-200">{assetCriticalityRating.replace('_', ' ')}</div>
                </div>
              )}
            </>
          ) : (
            assetCriticality && (
              <div>
                <div className="text-xs font-medium text-gray-700">Asset Criticality</div>
                <div className="text-xs mt-1 font-semibold bg-white px-2 py-1 rounded border border-gray-200">{assetCriticality}/10</div>
              </div>
            )
          )}
        </CardContent>
      </Card>

      {/* Auto-populated Data */}
      {(autoPopulatedData.epss || autoPopulatedData.cvss || autoPopulatedData.kev !== undefined || autoPopulatedData.patchAvailable !== undefined) && (
        <Card>
          <div className="mb-2 border-b border-gray-200 dark:border-dark-300 pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <CheckCircle2 className="h-3 w-3 text-green-600" />
              Auto-populated
            </CardTitle>
          </div>
          <CardContent className="space-y-2">
            {autoPopulatedData.epss && (
              <div className="flex justify-between text-xs">
                <span>EPSS Score</span>
                <span className="font-medium">{(autoPopulatedData.epss * 100).toFixed(1)}%</span>
              </div>
            )}
            {autoPopulatedData.cvss && (
              <div className="flex justify-between text-xs">
                <span>CVSS Score</span>
                <span className="font-medium">{autoPopulatedData.cvss.toFixed(1)}</span>
              </div>
            )}
            {autoPopulatedData.kev !== undefined && (
              <div className="flex justify-between text-xs">
                <span>Known Exploited</span>
                <span className={`font-medium ${autoPopulatedData.kev ? 'text-red-600' : 'text-green-600'}`}>
                  {autoPopulatedData.kev ? 'Yes' : 'No'}
                </span>
              </div>
            )}
            {autoPopulatedData.patchAvailable !== undefined && (
              <div className="flex justify-between text-xs">
                <span>Patch Available</span>
                <span className={`font-medium ${autoPopulatedData.patchAvailable ? 'text-green-600' : 'text-orange-600'}`}>
                  {autoPopulatedData.patchAvailable ? 'Yes' : 'No'}
                </span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Impact & Mitigation - contextual per framework */}
      {selectedFramework !== 'enhanced' && (
        (() => {
          if (selectedFramework === 'fedramp-vdr') {
            if (!(impactData.mitigation_level || impactData.mitigation_effectiveness !== undefined || impactData.federal_data_exposure || impactData.affected_users)) return null;
            return (
              <Card className="border border-gray-200 bg-white shadow-lg dark:border-gray-700 dark:bg-dark-500">
                <div className="mb-1 border-b border-gray-200 pb-2 bg-gray-50 rounded-t-lg dark:border-gray-700 dark:bg-dark-600">
                  <CardTitle className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                    <Settings className="h-4 w-4" />
                    Impact & Mitigation
                  </CardTitle>
                </div>
                <CardContent className="space-y-1 pt-1">
                  {impactData.mitigation_level && (
                    <div className="bg-gray-50 p-2 rounded border border-gray-200 dark:bg-dark-600 dark:border-gray-700">
                      <div className="text-xs font-medium text-gray-700 dark:text-gray-300">Mitigation Level</div>
                      <div className="text-xs capitalize font-semibold text-gray-900 dark:text-gray-100 mt-1">{impactData.mitigation_level}</div>
                    </div>
                  )}
                  {impactData.mitigation_effectiveness !== undefined && (
                    <div className="bg-gray-50 p-2 rounded border border-gray-200 dark:bg-dark-600 dark:border-gray-700">
                      <div className="text-xs font-medium text-gray-700 dark:text-gray-300">Effectiveness</div>
                      <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 mt-1">{Math.round((impactData.mitigation_effectiveness || 0) * 100)}%</div>
                    </div>
                  )}
                  {impactData.federal_data_exposure !== undefined && impactData.federal_data_exposure > 0 && (
                    <div className="bg-gray-50 p-2 rounded border border-gray-200 dark:bg-dark-600 dark:border-gray-700">
                      <div className="text-xs font-medium text-gray-700 dark:text-gray-300">Federal Data Exposure</div>
                      <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 mt-1">{impactData.federal_data_exposure}%</div>
                    </div>
                  )}
                  {impactData.affected_users !== undefined && impactData.affected_users > 0 && (
                    <div className="bg-gray-50 p-2 rounded border border-gray-200 dark:bg-dark-600 dark:border-gray-700">
                      <div className="text-xs font-medium text-gray-700 dark:text-gray-300">Affected Users</div>
                      <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 mt-1">{impactData.affected_users}%</div>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          }
          // Non-VDR frameworks: show controls summary instead of percentage
          const p = controlsSummary?.preventive || 0;
          const d = controlsSummary?.detective || 0;
          const r = controlsSummary?.response || 0;
          if (p + d + r === 0) return null;
          return (
            <Card className="border border-gray-200 bg-white shadow-lg dark:border-gray-700 dark:bg-dark-500">
              <div className="mb-1 border-b border-gray-200 pb-2 bg-gray-50 rounded-t-lg dark:border-gray-700 dark:bg-dark-600">
                <CardTitle className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Settings className="h-4 w-4" />
                  Controls Summary
                </CardTitle>
              </div>
              <CardContent className="space-y-1 pt-1">
                <div className="bg-gray-50 p-2 rounded border border-gray-200 dark:bg-dark-600 dark:border-gray-700 flex justify-between text-xs">
                  <span>Preventive</span>
                  <span className="font-semibold">{p}</span>
                </div>
                <div className="bg-gray-50 p-2 rounded border border-gray-200 dark:bg-dark-600 dark:border-gray-700 flex justify-between text-xs">
                  <span>Detective</span>
                  <span className="font-semibold">{d}</span>
                </div>
                <div className="bg-gray-50 p-2 rounded border border-gray-200 dark:bg-dark-600 dark:border-gray-700 flex justify-between text-xs">
                  <span>Response</span>
                  <span className="font-semibold">{r}</span>
                </div>
              </CardContent>
            </Card>
          );
        })()
      )}

      {/* Environment */}
      {(environmentData.reachability_paths?.length || environmentData.threat_intel_tags?.length || environmentData.internet_reachable) && (
        <Card>
          <div className="mb-2 border-b border-gray-200 dark:border-dark-300 pb-2">
            <CardTitle className="text-sm">Environment</CardTitle>
          </div>
          <CardContent className="space-y-2">
            {environmentData.internet_reachable && (
              <div className="flex justify-between text-xs">
                <span>Internet Reachable</span>
                <span className="font-medium text-orange-600">Yes</span>
              </div>
            )}
            {environmentData.reachability_paths && environmentData.reachability_paths.length > 0 && (
              <div>
                <div className="text-xs font-medium text-gray-600">Reachability Paths</div>
                <div className="text-xs text-gray-500 mt-1">
                  {environmentData.reachability_paths.slice(0, 2).join(', ')}
                  {environmentData.reachability_paths.length > 2 && ` +${environmentData.reachability_paths.length - 2} more`}
                </div>
              </div>
            )}
            {environmentData.threat_intel_tags && environmentData.threat_intel_tags.length > 0 && (
              <div>
                <div className="text-xs font-medium text-gray-600">Threat Intel</div>
                <div className="text-xs text-gray-500 mt-1">
                  {environmentData.threat_intel_tags.slice(0, 2).join(', ')}
                  {environmentData.threat_intel_tags.length > 2 && ` +${environmentData.threat_intel_tags.length - 2} more`}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Warnings */}
      {warnings.length > 0 && (
        <Card className="border-orange-200 bg-orange-50">
          <div className="mb-2 border-b border-gray-200 dark:border-dark-300 pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-orange-800">
              <AlertTriangle className="h-3 w-3" />
              Validation Warnings
            </CardTitle>
          </div>
          <CardContent>
            <ul className="space-y-1">
              {warnings.map((warning, index) => (
                <li key={index} className="text-xs text-orange-700">
                  • {warning}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Calculate Button - Made more prominent and positioned right */}
      <Button
        onClick={onCalculate}
        disabled={!canCalculate || isLoading}
        className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 h-10 text-sm font-semibold shadow-xl border-2 border-blue-500 transform hover:scale-105 transition-all duration-200"
        size="lg"
      >
        {isLoading ? (
          <>
            <Calculator className="mr-2 h-4 w-4 lg:h-5 lg:w-5 animate-pulse" />
            <span className="hidden sm:inline">Calculating Risk Score...</span>
            <span className="sm:hidden">Calculating...</span>
          </>
        ) : (
          <>
            <Calculator className="mr-2 h-4 w-4 lg:h-5 lg:w-5" />
            <span className="hidden sm:inline">Review & Calculate</span>
            <span className="sm:hidden">Calculate</span>
          </>
        )}
      </Button>
    </div>
  );
}

