// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';

interface CustomSpinnerProps {
  className?: string;
}

export const CustomSpinner: React.FC<CustomSpinnerProps> = ({
  className = 'w-10 h-10 text-[#c30800]',
}) => (
  <span
    className={`custom-spinner-icon inline-block animate-spin select-none ${className}`}
    aria-label="Processing..."
    role="status"
  />
);
