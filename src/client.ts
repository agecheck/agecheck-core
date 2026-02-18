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

import type { VerifyInput, VerifyResult } from "./types.js";
import { verifyAgeToken } from "./verify.js";

export class AgeCheckClient {
  public async verify(input: VerifyInput): Promise<VerifyResult> {
    return verifyAgeToken(input);
  }
}
