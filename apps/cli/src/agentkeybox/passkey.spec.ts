import { createHash, generateKeyPairSync, randomBytes, verify } from "node:crypto";

import { of } from "rxjs";

import { Fido2AuthenticatorService } from "@bitwarden/common/platform/services/fido2/fido2-authenticator.service";
import { CipherType } from "@bitwarden/common/vault/enums";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { Fido2CredentialView } from "@bitwarden/common/vault/models/view/fido2-credential.view";
import { LoginView } from "@bitwarden/common/vault/models/view/login.view";

import {
  assertionReply,
  clientData,
  FixedCredentialInterface,
  parseOrigin,
  parsePasskeyRegistration,
  parsePasskeyRequest,
  registrationReply,
} from "./passkey";

const challenge = randomBytes(32).toString("base64url");

describe("parseOrigin", () => {
  it("keeps only the origin of an https address", () => {
    expect(parseOrigin("https://example.com/login?next=/x#y")).toBe("https://example.com");
    expect(parseOrigin("https://login.example.com:8443/")).toBe("https://login.example.com:8443");
    expect(parseOrigin("http://localhost:3000/app")).toBe("http://localhost:3000");
  });

  it("refuses anything that is not a secure origin", () => {
    for (const bad of [
      undefined,
      "",
      "example.com",
      "http://example.com",
      "ftp://example.com",
      "https://user:pw@example.com",
      "http://localhost.evil.test",
    ]) {
      expect(() => parseOrigin(bad)).toThrow(expect.objectContaining({ code: "INVALID_ORIGIN" }));
    }
  });
});

describe("parsePasskeyRequest", () => {
  const good = { ref: "ref:site/login", origin: "https://example.com", challenge };

  it("accepts an exact reference, an origin and a base64url challenge", () => {
    expect(parsePasskeyRequest(good)).toEqual(good);
  });

  it("rejects what a browser would never send", () => {
    for (const bad of [
      "",
      "short",
      "has spaces in it which is not base64url",
      "a+b/c=".repeat(8),
    ]) {
      expect(() => parsePasskeyRequest({ ...good, challenge: bad })).toThrow(
        expect.objectContaining({ code: "INVALID_CHALLENGE" }),
      );
    }
    expect(() => parsePasskeyRequest({ ...good, challenge: "x".repeat(1025) })).toThrow(
      expect.objectContaining({ code: "INVALID_CHALLENGE" }),
    );
    expect(() => parsePasskeyRequest({ ...good, ref: "site" })).toThrow(
      expect.objectContaining({ code: "INVALID_REFERENCE" }),
    );
  });
});

describe("clientData", () => {
  it("is the client data a browser builds, and its SHA-256", () => {
    const { json, hash } = clientData("https://example.com", challenge);
    expect(JSON.parse(json)).toEqual({
      type: "webauthn.get",
      challenge,
      origin: "https://example.com",
      crossOrigin: false,
    });
    expect(hash.equals(createHash("sha256").update(json).digest())).toBe(true);
  });
});

/** A login holding a real P-256 passkey, as the vault would decrypt it. */
function passkeyLogin(rpId: string, counter = 0) {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const credentialId = Buffer.from(randomBytes(16));
  const credential = new Fido2CredentialView();
  Object.assign(credential, {
    credentialId: "b64." + credentialId.toString("base64url"),
    keyType: "public-key",
    keyAlgorithm: "ECDSA",
    keyCurve: "P-256",
    keyValue: pair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
    rpId,
    userHandle: randomBytes(16).toString("base64url"),
    counter,
    discoverable: true,
  });
  const view = new CipherView();
  view.id = "cipher-1";
  view.type = CipherType.Login;
  view.login = new LoginView();
  view.login.fido2Credentials = [credential];
  return { view, publicKey: pair.publicKey, credentialId };
}

function authenticatorFor(views: CipherView[]) {
  const updateWithServer = jest.fn().mockResolvedValue(undefined);
  const cipherService = { getAllDecrypted: jest.fn().mockResolvedValue(views), updateWithServer };
  const authenticator = new Fido2AuthenticatorService<void>(
    cipherService as never,
    new FixedCredentialInterface("cipher-1"),
    { fullSync: jest.fn().mockResolvedValue(true) } as never,
    { activeAccount$: of({ id: "user-1" }) } as never,
  );
  return { authenticator, updateWithServer };
}

function params(rpId: string, hash: Uint8Array<ArrayBuffer>, id: Buffer) {
  return {
    rpId,
    hash,
    allowCredentialDescriptorList: [{ id: new Uint8Array(id), type: "public-key" as const }],
    requireUserVerification: false,
    extensions: {},
    fallbackSupported: false,
    assumeUserPresence: true,
  };
}

describe("signing through the upstream authenticator", () => {
  it("produces a signature a site can verify with the public key", async () => {
    const { view, publicKey, credentialId } = passkeyLogin("example.com");
    const { authenticator } = authenticatorFor([view]);
    const { json, hash } = clientData("https://example.com", challenge);
    const signed = await authenticator.getAssertion(
      params("example.com", hash, credentialId),
      undefined,
    );
    const reply = assertionReply(signed, json, "example.com");

    const authData = Buffer.from(reply.authenticator_data, "base64url");
    // rpIdHash, then flags: user present set, user verified not set.
    expect(
      authData.subarray(0, 32).equals(createHash("sha256").update("example.com").digest()),
    ).toBe(true);
    expect(authData[32] & 0x01).toBe(1);
    expect(authData[32] & 0x04).toBe(0);
    const ok = verify(
      "sha256",
      Buffer.concat([authData, hash]),
      { key: publicKey, dsaEncoding: "der" },
      Buffer.from(reply.signature, "base64url"),
    );
    expect(ok).toBe(true);
    expect(reply.credential_id).toBe(credentialId.toString("base64url"));
    expect(JSON.parse(Buffer.from(reply.client_data_json, "base64url").toString())).toMatchObject({
      type: "webauthn.get",
      challenge,
      origin: "https://example.com",
    });
  });

  it("never puts the private key into its reply", async () => {
    const { view, credentialId } = passkeyLogin("example.com");
    const { authenticator } = authenticatorFor([view]);
    const { json, hash } = clientData("https://example.com", challenge);
    const signed = await authenticator.getAssertion(
      params("example.com", hash, credentialId),
      undefined,
    );
    const text = JSON.stringify(assertionReply(signed, json, "example.com"));
    expect(text).not.toContain(view.login.fido2Credentials[0].keyValue);
  });

  it("advances the counter and saves it when the passkey counts uses", async () => {
    const { view, credentialId } = passkeyLogin("example.com", 5);
    const { authenticator, updateWithServer } = authenticatorFor([view]);
    const { hash } = clientData("https://example.com", challenge);
    await authenticator.getAssertion(params("example.com", hash, credentialId), undefined);
    expect(view.login.fido2Credentials[0].counter).toBe(6);
    expect(updateWithServer).toHaveBeenCalledTimes(1);
  });

  it("does not sign for a credential it was not asked about", async () => {
    const { view } = passkeyLogin("example.com");
    const { authenticator } = authenticatorFor([view]);
    const { hash } = clientData("https://example.com", challenge);
    await expect(
      authenticator.getAssertion(params("example.com", hash, randomBytes(16)), undefined),
    ).rejects.toBeDefined();
  });
});

describe("FixedCredentialInterface", () => {
  it("picks only its own login and never claims user verification", async () => {
    const session = await new FixedCredentialInterface("cipher-1").newSession();
    await expect(
      session.pickCredential({ cipherIds: ["other", "cipher-1"], userVerification: false }),
    ).resolves.toEqual({ cipherId: "cipher-1", userVerified: false });
    await expect(
      session.pickCredential({ cipherIds: ["other"], userVerification: false }),
    ).rejects.toMatchObject({ code: "PASSKEY_UNAVAILABLE" });
  });

  it("hands a registration to the login it was made for, and says nothing was verified", async () => {
    const session = await new FixedCredentialInterface("cipher-1").newSession();
    await expect(
      session.confirmNewCredential({
        credentialName: "x",
        userName: "y",
        userHandle: "z",
        userVerification: false,
        rpId: "example.com",
      }),
    ).resolves.toEqual({ cipherId: "cipher-1", userVerified: false });
  });
});

describe("parsePasskeyRegistration", () => {
  const good = {
    ref: "ref:site/login",
    origin: "https://example.com/signup",
    challenge,
    user_id: randomBytes(16).toString("base64url"),
    user_name: "alice@example.com",
  };

  it("takes what a site sends and keeps only the origin", () => {
    expect(parsePasskeyRegistration(good)).toEqual({
      ref: "ref:site/login",
      origin: "https://example.com",
      challenge,
      userId: good.user_id,
      userName: "alice@example.com",
      displayName: undefined,
      rpName: undefined,
      rpId: undefined,
    });
    expect(
      parsePasskeyRegistration({
        ...good,
        display_name: "Alice",
        rp_name: "Example",
        rp_id: "example.com",
      }),
    ).toMatchObject({ displayName: "Alice", rpName: "Example", rpId: "example.com" });
  });

  it("rejects a malformed request before anything is created", () => {
    for (const bad of [
      { user_id: undefined },
      { user_id: "not base64url!" },
      { user_id: "x".repeat(87) },
      { user_name: undefined },
      { user_name: "   " },
      { user_name: "a\nb" },
      { rp_id: "bad host" },
      { display_name: "x".repeat(201) },
      { origin: "http://example.com" },
      { challenge: "short" },
    ]) {
      expect(() => parsePasskeyRegistration({ ...good, ...bad } as never)).toThrow();
    }
  });
});

describe("registrationReply", () => {
  it("is public material only, in the form the server of a site reads", () => {
    const bytes = (...values: number[]) => new Uint8Array(values);
    const reply = registrationReply(
      {
        credentialId: bytes(1, 2, 3),
        attestationObject: bytes(4, 5),
        authData: bytes(6),
        publicKey: bytes(7, 8),
        publicKeyAlgorithm: -7,
      },
      '{"type":"webauthn.create"}',
      "example.com",
    );
    expect(reply).toEqual({
      rp_id: "example.com",
      credential_id: "AQID",
      client_data_json: Buffer.from('{"type":"webauthn.create"}').toString("base64url"),
      attestation_object: "BAU",
      authenticator_data: "Bg",
      public_key: "Bwg",
      public_key_algorithm: -7,
      transports: ["internal"],
    });
  });

  it("builds client data for a registration", () => {
    const { json } = clientData("https://example.com", challenge, "webauthn.create");
    expect(JSON.parse(json).type).toBe("webauthn.create");
  });
});
