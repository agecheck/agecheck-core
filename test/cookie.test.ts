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
import { createVerifiedCookieValue, formatSetCookieHeader, verifySignedCookieValue } from "../src/cookie.js";

const claims = {
  iss: "did:web:agecheck.me",
  sub: "did:key:abc",
  vc: {
    credentialSubject: {
      ageTier: "21+",
    },
  },
};

describe("signed cookie helpers", () => {
  it("creates and verifies a signed cookie", async () => {
    const created = await createVerifiedCookieValue(claims, { secret: "x".repeat(32) });
    const verified = await verifySignedCookieValue(created.cookieValue, { secret: "x".repeat(32) });

    expect(verified).not.toBeNull();
    expect(verified?.verified).toBe(true);
    expect(verified?.level).toBe("21+");
  });

  it("rejects tampered cookie values", async () => {
    const created = await createVerifiedCookieValue(claims, { secret: "x".repeat(32) });
    const tampered = `${created.cookieValue}bad`;
    const verified = await verifySignedCookieValue(tampered, { secret: "x".repeat(32) });

    expect(verified).toBeNull();
  });

  it("formats secure cookie attributes with max-age", () => {
    const header = formatSetCookieHeader("agecheck_verified", "abc.def", 1700000000, 86400);
    expect(header).toContain("Path=/");
    expect(header).toContain("Max-Age=86400");
    expect(header).toContain("HttpOnly");
    expect(header).toContain("Secure");
    expect(header).toContain("SameSite=Lax");
  });
});
