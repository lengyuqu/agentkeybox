import {
  credentialValue,
  metadata,
  normalizeUrl,
  parseSecretSpec,
  parseSecretSpecs,
  resolveSecrets,
  TotpGenerator,
} from "./protocol";

const items = [
  {
    id: "one",
    name: "GitHub",
    login: {
      username: "user",
      password: "pw-1",
      totp: "JBSWY3DPEHPK3PXP",
      uris: [
        { uri: "https://github.com/login?token=abc123&next=/x" },
        { uri: "https://github.com/session" },
        { uri: "androidapp://com.github.android" },
        { uri: "not an address" },
        { uri: undefined },
      ],
    },
    fields: [{ name: "agentkeybox.ref", value: "app/one" }],
  },
  {
    id: "two",
    login: { password: "pw-2" },
    fields: [{ name: "agentkeybox.ref", value: "app/two" }],
  },
];

const generator: TotpGenerator = jest.fn(async (_seed, minValidSeconds) => ({
  code: "123456",
  expiresIn: Math.max(minValidSeconds, 20),
}));

describe("discovery metadata", () => {
  it("shows only the origin of each address, never paths or query strings", () => {
    const shown = metadata(items[0]);
    expect(shown.uris).toEqual(["https://github.com", "androidapp://com.github.android"]);
    expect(JSON.stringify(shown)).not.toContain("abc123");
    expect(JSON.stringify(shown)).not.toContain("/login");
  });

  it("lists totp as a readable field without exposing the seed", () => {
    const shown = metadata(items[0]);
    expect(shown.credential_fields).toContain("totp");
    expect(JSON.stringify(shown)).not.toContain("JBSWY3DPEHPK3PXP");
    expect(metadata(items[1]).credential_fields).not.toContain("totp");
    expect(metadata(items[1]).uris).toEqual([]);
  });

  it("treats a blank seed as no totp", () => {
    expect(metadata({ id: "x", login: { password: "p", totp: "  " } }).credential_fields).toEqual([
      "password",
    ]);
  });
});

describe("normalizeUrl", () => {
  it("passes through nothing when no address was given", () => {
    expect(normalizeUrl(undefined)).toBeUndefined();
  });

  it("keeps an address and completes a bare domain", () => {
    expect(normalizeUrl("https://github.com/login")).toBe("https://github.com/login");
    expect(normalizeUrl("  github.com ")).toBe("https://github.com");
    expect(normalizeUrl("androidapp://com.github.android")).toBe("androidapp://com.github.android");
  });

  it("rejects unusable input without echoing it", () => {
    for (const bad of ["", "   ", "http://", "x".repeat(3000)]) {
      expect(() => normalizeUrl(bad)).toThrow("valid URL");
    }
    try {
      normalizeUrl("http://");
    } catch (error) {
      expect((error as Error).message).not.toContain("http://");
    }
  });
});

describe("totp fields", () => {
  it("accepts #totp in a secret specification", () => {
    expect(parseSecretSpec("OTP=ref:app/one#totp")).toEqual({
      name: "OTP",
      ref: "ref:app/one",
      field: "totp",
    });
    expect(parseSecretSpecs(["OTP=id:one#totp"])[0].field).toBe("totp");
  });

  it("returns the code and how long it stays valid", async () => {
    await expect(credentialValue(items[0], "totp", generator, 0)).resolves.toEqual({
      value: "123456",
      expiresIn: 20,
    });
  });

  it("asks the generator for a code that outlives the command start-up", async () => {
    await credentialValue(items[0], "totp", generator, 3);
    expect(generator).toHaveBeenLastCalledWith("JBSWY3DPEHPK3PXP", 3);
  });

  it("does not add timing information to other fields", async () => {
    await expect(credentialValue(items[0], "password")).resolves.toEqual({ value: "pw-1" });
  });

  it("reports a missing seed without calling the generator", async () => {
    const spy = jest.fn();
    await expect(credentialValue(items[1], "totp", spy)).rejects.toMatchObject({
      code: "FIELD_NOT_FOUND",
    });
    expect(spy).not.toHaveBeenCalled();
  });

  it("honours restricted visibility", async () => {
    await expect(
      credentialValue({ ...items[0], viewPassword: false }, "totp", generator),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("fails without leaking the seed when no code can be generated", async () => {
    const failing: TotpGenerator = async () => undefined;
    const error = await credentialValue(items[0], "totp", failing).catch((e: Error) => e);
    expect(error).toMatchObject({ code: "TOTP_FAILED" });
    expect((error as Error).message).not.toContain("JBSWY3DPEHPK3PXP");
    await expect(credentialValue(items[0], "totp")).rejects.toMatchObject({ code: "TOTP_FAILED" });
  });
});

describe("resolveSecrets", () => {
  it("resolves every specification, including one-time codes", async () => {
    await expect(
      resolveSecrets(
        items,
        parseSecretSpecs(["A=ref:app/one", "B=ref:app/two", "C=id:one#username", "D=id:one#totp"]),
        generator,
      ),
    ).resolves.toEqual({ A: "pw-1", B: "pw-2", C: "user", D: "123456" });
  });

  it("asks for a code that stays valid long enough for a command to start", async () => {
    await resolveSecrets(items, parseSecretSpecs(["D=id:one#totp"]), generator);
    expect(generator).toHaveBeenLastCalledWith("JBSWY3DPEHPK3PXP", 3);
  });

  it("fails as a whole when any reference cannot be resolved", async () => {
    await expect(
      resolveSecrets(items, parseSecretSpecs(["A=ref:app/one", "B=ref:missing"]), generator),
    ).rejects.toThrow("not found");
    await expect(resolveSecrets(items, parseSecretSpecs(["A=id:two#username"]))).rejects.toThrow(
      "not found",
    );
  });
});
