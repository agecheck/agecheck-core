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

import { describe, expect, it } from "vitest";
import { isGateRequired } from "../src/gate.js";

describe("isGateRequired", () => {
  it("returns false when header is missing", () => {
    const headers = new Headers();
    expect(isGateRequired(headers)).toBe(false);
  });

  it("returns true when header matches required value", () => {
    const headers = new Headers({ "X-Age-Gate": "true" });
    expect(isGateRequired(headers)).toBe(true);
  });
});
