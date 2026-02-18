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
import { AgeCheckSdk } from "../src/sdk.js";
import { createVerifiedCookieValue } from "../src/cookie.js";

function makeSdk(): AgeCheckSdk {
  return new AgeCheckSdk({
    deploymentMode: "production",
    cookie: {
      secret: "s".repeat(32),
      cookieName: "agecheck_verified",
      ttlSeconds: 3600,
    },
    gate: {
      headerName: "X-Age-Gate",
      requiredValue: "true",
    },
    verify: {
      requiredAge: 18,
    },
  });
}

describe("AgeCheckSdk.renderGatePage", () => {
  it("renders standard gate page with agegate bundle", () => {
    const sdk = makeSdk();
    const html = sdk.renderGatePage({ redirect: "/protected", easyAgeGate: false });

    expect(html).toContain("agegate.min.js");
    expect(html).not.toContain("easy-agegate.min.js");
    expect(html).toContain("window.AgeCheck.launchAgeGate");
  });

  it("renders easy-agegate page when enabled", () => {
    const sdk = makeSdk();
    const html = sdk.renderGatePage({
      redirect: "/protected",
      easyAgeGate: true,
      easyAgeGateOptions: {
        title: "Age Restricted Content",
        verifyButtonText: "Verify Now",
      },
    });

    expect(html).toContain("easy-agegate.min.js");
    expect(html).toContain("window.AgeCheck.AgeGate.init");
    expect(html).toContain("Age Restricted Content");
    expect(html).toContain("Verify Now");
  });
});

describe("AgeCheckSdk.shouldGate", () => {
  it("forces gate when deploymentMode is demo", () => {
    const sdk = new AgeCheckSdk({
      deploymentMode: "demo",
      cookie: {
        secret: "s".repeat(32),
      },
      gate: {
        headerName: "X-Age-Gate",
        requiredValue: "true",
      },
    });

    const req = new Request("https://example.com/protected", {
      headers: new Headers({ "X-Age-Gate": "false" }),
    });

    expect(sdk.shouldGate(req)).toBe(true);
  });
});

describe("AgeCheckSdk.requireVerifiedOrRedirect", () => {
  it("returns null when gate is not required", async () => {
    const sdk = makeSdk();
    const req = new Request("https://example.com/protected", {
      headers: new Headers({ "X-Age-Gate": "false" }),
    });
    const result = await sdk.requireVerifiedOrRedirect(req);
    expect(result).toBeNull();
  });

  it("returns redirect response when gate is required and cookie missing", async () => {
    const sdk = makeSdk();
    const req = new Request("https://example.com/protected?a=1", {
      headers: new Headers({ "X-Age-Gate": "true" }),
    });
    const result = await sdk.requireVerifiedOrRedirect(req, { gatePath: "/ageverify" });
    expect(result).not.toBeNull();
    expect(result?.status).toBe(302);
    expect(result?.headers.get("location")).toBe("https://example.com/ageverify?redirect=%2Fprotected%3Fa%3D1");
  });

  it("returns null when valid signed cookie is present", async () => {
    const sdk = makeSdk();
    const claims = {
      vc: {
        credentialSubject: {
          ageTier: "21+",
        },
      },
    };
    const created = await createVerifiedCookieValue(claims, {
      secret: "s".repeat(32),
      cookieName: "agecheck_verified",
      ttlSeconds: 3600,
    });
    const req = new Request("https://example.com/protected", {
      headers: new Headers({
        "X-Age-Gate": "true",
        cookie: `agecheck_verified=${created.cookieValue}`,
      }),
    });
    const result = await sdk.requireVerifiedOrRedirect(req);
    expect(result).toBeNull();
  });
});
