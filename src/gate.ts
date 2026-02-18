/*
 * AgeCheck-core
 * Copyright (c) 2026 ReallyMe LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import type { AgeCheckGateConfig } from "./types.js";

const DEFAULT_HEADER_NAME = "X-Age-Gate";
const DEFAULT_REQUIRED_VALUE = "true";

export function isGateRequired(headers: Headers, cfg: AgeCheckGateConfig = {}): boolean {
  const headerName = cfg.headerName ?? DEFAULT_HEADER_NAME;
  const requiredValue = (cfg.requiredValue ?? DEFAULT_REQUIRED_VALUE).trim().toLowerCase();
  const currentValue = headers.get(headerName);

  if (currentValue === null) {
    return false;
  }

  return currentValue.trim().toLowerCase() === requiredValue;
}
