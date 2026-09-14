import { Check } from 'lucide-react';
import { cn } from '@/lib/utils';

type StepperProps = {
  currentStep: number;
  steps: Array<{
    id: number;
    title: string;
    description: string;
  }>;
};

export function RiskStepper({ currentStep, steps }: StepperProps) {
  return (
    <div className="w-full">
      <div className="flex items-center justify-between">
        {steps.map((step, index) => (
          <div key={step.id} className="flex items-center">
            <div className="flex flex-col items-center">
              <div
                className={cn(
                  'flex h-10 w-10 items-center justify-center rounded-full border-2 transition-colors',
                  currentStep > step.id
                    ? 'border-blue-600 bg-blue-600 text-white'
                    : currentStep === step.id
                    ? 'border-blue-600 bg-white text-blue-600'
                    : 'border-gray-300 bg-white text-gray-300'
                )}
              >
                {currentStep > step.id ? (
                  <Check className="h-5 w-5" />
                ) : (
                  <span className="text-sm font-medium">{step.id}</span>
                )}
              </div>
              <div className="mt-2 text-center">
                <div
                  className={cn(
                    'text-sm font-medium',
                    currentStep >= step.id ? 'text-gray-900' : 'text-gray-500'
                  )}
                >
                  {step.title}
                </div>
                <div className="text-xs text-gray-500 mt-1 max-w-20">
                  {step.description}
                </div>
              </div>
            </div>
            {index < steps.length - 1 && (
              <div
                className={cn(
                  'h-px w-20 mx-4 transition-colors',
                  currentStep > step.id ? 'bg-blue-600' : 'bg-gray-300'
                )}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

