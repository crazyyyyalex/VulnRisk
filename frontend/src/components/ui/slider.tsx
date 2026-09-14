import React from 'react';

interface SliderProps {
  value: number[];
  onValueChange: (value: number[]) => void;
  min?: number;
  max?: number;
  step?: number;
}

export const Slider: React.FC<SliderProps> = ({ value, onValueChange, min = 1, max = 10, step = 1 }) => (
  <input
    type="range"
    min={min}
    max={max}
    step={step}
    value={value[0]}
    onChange={e => onValueChange([parseInt(e.target.value, 10)])}
    className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
    title="Asset Criticality"
    placeholder="Asset Criticality"
  />
); 