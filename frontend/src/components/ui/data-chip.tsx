import { Loader2, AlertCircle, CheckCircle2, TrendingUp, Shield, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';

type DataChipVariant = 'epss' | 'cvss' | 'kev' | 'patch';
type DataChipState = 'loading' | 'ok' | 'error';

type DataChipProps = {
  variant: DataChipVariant;
  state: DataChipState;
  value?: string | number;
  subtitle?: string;
  className?: string;
};

const chipConfig = {
  epss: {
    icon: TrendingUp,
    label: 'EPSS',
    colors: {
      loading: 'bg-gray-100 text-gray-500',
      ok: 'bg-orange-100 text-orange-700 border-orange-200',
      error: 'bg-red-100 text-red-700 border-red-200'
    }
  },
  cvss: {
    icon: AlertTriangle,
    label: 'CVSS',
    colors: {
      loading: 'bg-gray-100 text-gray-500',
      ok: 'bg-red-100 text-red-700 border-red-200',
      error: 'bg-red-100 text-red-700 border-red-200'
    }
  },
  kev: {
    icon: AlertCircle,
    label: 'KEV',
    colors: {
      loading: 'bg-gray-100 text-gray-500',
      ok: 'bg-purple-100 text-purple-700 border-purple-200',
      error: 'bg-red-100 text-red-700 border-red-200'
    }
  },
  patch: {
    icon: Shield,
    label: 'Patch',
    colors: {
      loading: 'bg-gray-100 text-gray-500',
      ok: 'bg-green-100 text-green-700 border-green-200',
      error: 'bg-red-100 text-red-700 border-red-200'
    }
  }
};

export function DataChip({ variant, state, value, subtitle, className }: DataChipProps) {
  const config = chipConfig[variant];
  const Icon = config.icon;

  return (
    <div className={cn(
      'inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium transition-colors',
      config.colors[state],
      className
    )}>
      {state === 'loading' ? (
        <Loader2 className="h-4 w-4 animate-spin" />
      ) : (
        <Icon className="h-4 w-4" />
      )}
      <div className="flex flex-col">
        <span className="font-medium">{config.label}</span>
        {state === 'loading' ? (
          <span className="text-xs opacity-70">Loading...</span>
        ) : state === 'error' ? (
          <span className="text-xs opacity-70">Error</span>
        ) : (
          <>
            {value && <span className="text-xs font-bold">{value}</span>}
            {subtitle && <span className="text-xs opacity-70">{subtitle}</span>}
          </>
        )}
      </div>
    </div>
  );
}

