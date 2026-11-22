import { createHash } from "node:crypto";

import {
  Fido2AuthenticatorGetAssertionResult,
  Fido2AuthenticatorMakeCredentialResult,
} from "@bitwarden/common/platform/abstractions/fido2/fido2-authenticator.service.abstraction";
import {
  Fido2UserInterfaceService,
  Fido2UserInterfaceSession,
} from "@bitwarden/common/platform/abstractions/fido2/fido2-user-interface.service.abstraction";
import { Fido2Utils } from "@bitwarden/common/platform/services/fido2/fido2-utils";

import { AkbError } from "./protocol";
import { parseExactRef } from "./write";

/**
 * Signing in with a passkey proves possession of a private key by signing a site's challenge.
 * The key stays in the vault: AKB asks the upstream authenticator to sign, and only the signed
 * response, which is what a browser would send to the site anyway, leaves this process.
 */

export interface PasskeyRequest {
  /** The login that holds the passkey: `ref:<name>` or `id:<uuid>`. */
  ref: string;
  /** Where the sign-in happens, reduced to scheme, host and port. */
  origin: string;
  /** The site's challenge as sent to the browser: base64url text. */
  challenge: string;
}

const CHALLENGE = /^[A-Za-z0-9_-]{16,1024}$/;

function invalid(code: string, message: string): AkbError {
  return new AkbError(code, message, 2);
}

/** Only an https origin may ask for a signature; localhost is allowed for development. */
export function parseOrigin(input: string | undefined): string {
  let url: URL;
  try {
    url = new URL(input ?? "");
  } catch {
    throw invalid("INVALID_ORIGIN", "Provide the site's origin, for example https://example.com.");
  }
  const secure =
    url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost");
  if (!secure || !url.hostname || url.username || url.password) {
    throw invalid("INVALID_ORIGIN", "The origin must be an https address.");
  }
  return url.origin;
}

export function parsePasskeyRequest(args: Record<string, string>): PasskeyRequest {
  const challenge = args.challenge;
  if (challenge === undefined || !CHALLENGE.test(challenge)) {
    throw invalid("INVALID_CHALLENGE", "Provide the challenge as base64url text.");
  }
  return { ref: parseExactRef(args.ref), origin: parseOrigin(args.origin), challenge };
}

/** The client data a browser would build, and its hash, which is what actually gets signed. */
export function clientData(
  origin: string,
  challenge: string,
  type: "webauthn.get" | "webauthn.create" = "webauthn.get",
) {
  const json = JSON.stringify({ type, challenge, origin, crossOrigin: false });
  return { json, hash: createHash("sha256").update(json, "latin1").digest() };
}

export interface PasskeyRegistration extends PasskeyRequest {
  /** The site's user handle (`user.id`), base64url. It is stored with the passkey. */
  userId: string;
  userName: string;
  displayName?: string;
  /** The site's name for itself. */
  rpName?: string;
  /** Defaults to the origin's host. */
  rpId?: string;
}

const USER_ID = /^[A-Za-z0-9_-]{1,86}$/;
const HOST = /^[A-Za-z0-9.-]{1,253}$/;

// A label is shown to people, so control characters have no place in it.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f]/;

function label(value: string | undefined, name: string): string | undefined {
  if (value !== undefined && (value.trim() === "" || value.length > 200 || CONTROL.test(value))) {
    throw invalid("INVALID_ARGUMENT", `Provide ${name} as text of up to 200 characters.`);
  }
  return value;
}

/** What a site sends to create a passkey, reduced to what AKB needs. */
export function parsePasskeyRegistration(args: Record<string, string>): PasskeyRegistration {
  const request = parsePasskeyRequest(args);
  if (args.user_id === undefined || !USER_ID.test(args.user_id)) {
    throw invalid("INVALID_ARGUMENT", "Provide the site's user id as base64url text.");
  }
  if (args.rp_id !== undefined && !HOST.test(args.rp_id)) {
    throw invalid("INVALID_ARGUMENT", "Provide the site's id as a host name.");
  }
  const userName = label(args.user_name, "the user name");
  if (userName === undefined) {
    throw invalid("INVALID_ARGUMENT", "Provide the user name the site shows for this account.");
  }
  return {
    ...request,
    userId: args.user_id,
    userName,
    displayName: label(args.display_name, "the display name"),
    rpName: label(args.rp_name, "the site name"),
    rpId: args.rp_id,
  };
}

/** What the site's server needs to complete a registration. All of it is public. */
export function registrationReply(
  result: Fido2AuthenticatorMakeCredentialResult,
  clientDataJSON: string,
  rpId: string,
) {
  const text = (bytes: Uint8Array<ArrayBuffer>) => Fido2Utils.arrayToString(bytes);
  return {
    rp_id: rpId,
    credential_id: text(result.credentialId),
    client_data_json: Buffer.from(clientDataJSON, "latin1").toString("base64url"),
    attestation_object: text(result.attestationObject),
    authenticator_data: text(result.authData),
    public_key: text(result.publicKey),
    public_key_algorithm: result.publicKeyAlgorithm,
    transports: ["internal"],
  };
}

/** What the site's server needs to verify the sign-in. Everything here is public. */
export function assertionReply(
  result: Fido2AuthenticatorGetAssertionResult,
  clientDataJSON: string,
  rpId: string,
) {
  const text = (bytes: Uint8Array<ArrayBuffer>) => Fido2Utils.arrayToString(bytes);
  return {
    rp_id: rpId,
    credential_id: text(result.selectedCredential.id),
    client_data_json: Buffer.from(clientDataJSON, "latin1").toString("base64url"),
    authenticator_data: text(result.authenticatorData),
    signature: text(result.signature),
    ...(result.selectedCredential.userHandle
      ? { user_handle: text(result.selectedCredential.userHandle) }
      : {}),
  };
}

/**
 * Answers the authenticator's questions without a person: the login was already chosen by the
 * caller. It never claims the user was verified, so a site that requires verification refuses.
 * Registering a passkey goes to that same login; the caller checks it has none yet.
 */
export class FixedCredentialInterface implements Fido2UserInterfaceService<void> {
  constructor(private readonly cipherId: string) {}

  async newSession(): Promise<Fido2UserInterfaceSession> {
    const refuse = (): never => {
      throw new AkbError("PASSKEY_UNAVAILABLE", "This passkey cannot be used here.", 7);
    };
    return {
      pickCredential: async ({ cipherIds }) => {
        if (!cipherIds.includes(this.cipherId)) {
          refuse();
        }
        return { cipherId: this.cipherId, userVerified: false };
      },
      // The login that receives the passkey was chosen by the caller, not by this prompt.
      confirmNewCredential: async () => ({ cipherId: this.cipherId, userVerified: false }),
      ensureUnlockedVault: async () => {},
      informExcludedCredential: async () => {},
      informCredentialNotFound: async () => {},
      close: () => {},
    };
  }
}
