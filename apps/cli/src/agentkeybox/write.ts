import { CipherExport } from "@bitwarden/common/models/export/cipher.export";
import { FieldExport } from "@bitwarden/common/models/export/field.export";
import { LoginUriExport } from "@bitwarden/common/models/export/login-uri.export";
import { LoginExport } from "@bitwarden/common/models/export/login.export";
import { SshKeyExport } from "@bitwarden/common/models/export/ssh-key.export";
import { CipherType, FieldType } from "@bitwarden/common/vault/enums";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";

import { AkbError, Item, normalizeUrl, reference } from "./protocol";

/** Custom fields under this prefix belong to AKB itself and cannot be edited through `set`. */
export const RESERVED_FIELD_PREFIX = "agentkeybox.";
const REFERENCE_FIELD = `${RESERVED_FIELD_PREFIX}ref`;

const MAX_VALUE_BYTES = 64 * 1024;
const MAX_NAME_LENGTH = 200;
const MAX_URLS = 16;
const DEFAULT_PASSWORD_LENGTH = 24;

export interface NewLogin {
  name: string;
  ref: string;
  username?: string;
  urls: string[];
  /** Present when the caller supplied the password. Otherwise the vault generates one. */
  password?: string;
  generate: boolean;
  length: number;
}

export interface FieldChange {
  ref: string;
  field: string;
  /** Present when the caller supplied the value. Otherwise the vault generates a password. */
  value?: string;
  generate: boolean;
  length: number;
}

export interface NewSshKey {
  name: string;
  ref: string;
  /** Present when the caller supplied the private key. Otherwise AKB generates a key pair. */
  privateKey?: string;
  generate: boolean;
}

/** A private key with the public key and fingerprint the SDK derived from it. */
export interface SshKeyMaterial {
  privateKey: string;
  publicKey: string;
  keyFingerprint: string;
}

function invalid(message: string): AkbError {
  return new AkbError("INVALID_ARGUMENT", message, 2);
}

function parseLength(text: string | undefined): number {
  if (text === undefined) {
    return DEFAULT_PASSWORD_LENGTH;
  }
  const length = Number(text);
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw invalid("Password length must be a whole number from 8 to 128.");
  }
  return length;
}

function checkSize(value: string) {
  if (Buffer.byteLength(value) > MAX_VALUE_BYTES) {
    throw new AkbError("INPUT_TOO_LARGE", "Value exceeds the size limit.", 2);
  }
}

/** A reference is the text after `ref:`. Accept it with or without the prefix. */
export function parseReferenceName(input: string | undefined): string {
  const name = input?.startsWith("ref:") ? input.slice(4) : input;
  // Control characters would make a reference impossible to type back in.
  // eslint-disable-next-line no-control-regex
  if (!name?.trim() || name.length > MAX_NAME_LENGTH || /[\u0000-\u001f]/.test(name)) {
    throw invalid("Provide a reference of up to 200 characters, without control characters.");
  }
  return name;
}

export function parseNewLogin(args: Record<string, string>): NewLogin {
  const name = args.name?.trim();
  if (!name || name.length > MAX_NAME_LENGTH) {
    throw invalid("Provide a name of up to 200 characters.");
  }
  let urls: unknown;
  try {
    urls = args.urls === undefined ? [] : JSON.parse(args.urls);
  } catch {
    urls = undefined;
  }
  if (
    !Array.isArray(urls) ||
    urls.length > MAX_URLS ||
    urls.some((url) => typeof url !== "string")
  ) {
    throw invalid("Provide up to 16 addresses.");
  }
  const generate = args.generate === "1";
  if (generate === (args.password !== undefined)) {
    throw invalid("Provide the password on standard input, or ask for a generated one.");
  }
  for (const value of [args.password, args.username]) {
    if (value !== undefined) {
      checkSize(value);
    }
  }
  return {
    name,
    ref: parseReferenceName(args.ref),
    username: args.username,
    urls: (urls as string[]).map((url) => normalizeUrl(url) as string),
    password: args.password,
    generate,
    length: parseLength(args.length),
  };
}

export function parseNewSshKey(args: Record<string, string>): NewSshKey {
  const name = args.name?.trim();
  if (!name || name.length > MAX_NAME_LENGTH) {
    throw invalid("Provide a name of up to 200 characters.");
  }
  const generate = args.generate === "1";
  if (generate === (args.privateKey !== undefined)) {
    throw invalid("Provide the private key on standard input, or ask for a generated one.");
  }
  if (args.privateKey !== undefined) {
    checkSize(args.privateKey);
  }
  return { name, ref: parseReferenceName(args.ref), privateKey: args.privateKey, generate };
}

/**
 * The seed formats the upstream TOTP service documents: a base32 secret, an `otpauth://totp/`
 * address with a secret, or a `steam://` secret. The SDK will produce a "code" from almost any
 * text, so trying to generate one proves nothing about the seed. Check its shape here.
 */
export function isTotpSeed(value: string): boolean {
  const seed = value.trim();
  if (/^otpauth:\/\/totp\//i.test(seed)) {
    try {
      return !!new URL(seed).searchParams.get("secret");
    } catch {
      return false;
    }
  }
  const secret = seed.replace(/^steam:\/\//i, "").replace(/[\s-]/g, "");
  return /^[A-Za-z2-7]{8,}=*$/.test(secret);
}

const CHANGEABLE = /^(password|username|notes|totp|private_key|custom:.+)$/;

export function parseFieldChange(args: Record<string, string>): FieldChange {
  const field = args.field;
  if (!field || !CHANGEABLE.test(field)) {
    throw invalid("Use password, username, notes, totp or custom:<name>.");
  }
  if (field.startsWith(`custom:${RESERVED_FIELD_PREFIX}`)) {
    throw new AkbError("RESERVED_FIELD", "This field is managed by AgentKeybox.", 2);
  }
  const generate = args.generate === "1";
  if (generate && field !== "password" && field !== "private_key") {
    throw invalid("Only the password and private_key fields can be generated.");
  }
  if (generate === (args.value !== undefined)) {
    throw invalid("Provide the value on standard input, or ask for a generated password.");
  }
  if (args.value !== undefined) {
    checkSize(args.value);
  }
  if (field === "totp" && args.value !== undefined && !isTotpSeed(args.value)) {
    // The message never repeats the value: a rejected seed is still a secret.
    throw new AkbError(
      "INVALID_TOTP",
      "Use a base32 secret, an otpauth://totp/ address or a steam:// secret.",
      2,
    );
  }
  return {
    ref: args.ref,
    field,
    value: args.value,
    generate,
    length: parseLength(args.length),
  };
}

/** Build the request the way `bw create item` does, so the SDK sees an ordinary login. */
export function newLoginView(login: NewLogin, password: string): CipherView {
  const request = CipherExport.template();
  request.name = login.name;
  request.notes = undefined;
  request.fields = [
    Object.assign(new FieldExport(), {
      name: REFERENCE_FIELD,
      value: login.ref,
      type: FieldType.Text,
    }),
  ];
  const credentials = new LoginExport();
  credentials.username = login.username;
  credentials.password = password;
  credentials.uris = login.urls.map((uri) => Object.assign(new LoginUriExport(), { uri }));
  credentials.fido2Credentials = [];
  request.login = credentials;
  return CipherExport.toView(request);
}

/** Build an SSH key item. The key material comes from the SDK, never from the reply. */
export function newSshKeyView(key: NewSshKey, material: SshKeyMaterial): CipherView {
  const request = CipherExport.template();
  request.type = CipherType.SshKey;
  request.name = key.name;
  request.notes = undefined;
  request.fields = [
    Object.assign(new FieldExport(), {
      name: REFERENCE_FIELD,
      value: key.ref,
      type: FieldType.Text,
    }),
  ];
  request.sshKey = Object.assign(new SshKeyExport(), material);
  return CipherExport.toView(request);
}

/** Replace the whole key pair: the public key and fingerprint belong to the private key. */
export function applySshKey(view: CipherView, material: SshKeyMaterial) {
  assertEditable(view);
  if (view.type !== CipherType.SshKey || view.sshKey == null) {
    throw new AkbError(
      "UNSUPPORTED_FIELD",
      "A private key can only be set on an SSH key item.",
      10,
    );
  }
  view.sshKey.privateKey = material.privateKey;
  view.sshKey.publicKey = material.publicKey;
  view.sshKey.keyFingerprint = material.keyFingerprint;
}

/** A reference names one login. Creating a second one with the same name would be ambiguous. */
export function assertReferenceFree(items: Item[], ref: string) {
  if (items.some((item) => !item.isDeleted && !item.deletedDate && reference(item) === ref)) {
    throw new AkbError("REF_EXISTS", "An item with this reference already exists.", 6);
  }
}

/** The server marks items the user may not change, such as a read-only shared collection. */
export function assertEditable(view: { edit?: boolean }) {
  if (view.edit === false) {
    throw new AkbError("PERMISSION_DENIED", "This item is read-only.", 7);
  }
}

/** Deleting needs an exact reference: a search or a partial name is never enough. */
export function parseExactRef(ref: string | undefined): string {
  if (!ref || !/^(id:|ref:)./.test(ref) || ref.length > MAX_NAME_LENGTH + 4) {
    throw new AkbError("INVALID_REFERENCE", "Use id:<uuid> or ref:<exact-reference>.", 2);
  }
  return ref;
}

/**
 * Change one field of an existing item and leave every other part of it as it is. The item
 * is written back through the upstream SDK, which owns the data model.
 */
export function applyField(view: CipherView, field: string, value: string) {
  assertEditable(view);
  if (field === "notes") {
    view.notes = value;
    return;
  }
  if (view.type !== CipherType.Login || view.login == null) {
    throw new AkbError("UNSUPPORTED_FIELD", "This field can only be changed on a login.", 10);
  }
  switch (field) {
    case "password":
      view.login.password = value;
      return;
    case "username":
      view.login.username = value;
      return;
    case "totp":
      view.login.totp = value.trim();
      return;
  }
  const name = field.slice("custom:".length);
  const matches = (view.fields ?? []).filter((candidate) => candidate.name === name);
  if (matches.length > 1) {
    throw new AkbError("AMBIGUOUS_FIELD", "Custom field name is not unique.", 6);
  }
  if (matches[0]?.type === FieldType.Linked) {
    throw new AkbError("UNSUPPORTED_FIELD", "Linked fields cannot be changed.", 10);
  }
  if (matches[0]) {
    matches[0].value = value;
    return;
  }
  // A new custom field is hidden by default: it is more likely a secret than a label.
  view.fields = [
    ...(view.fields ?? []),
    FieldExport.toView(Object.assign(new FieldExport(), { name, value, type: FieldType.Hidden })),
  ];
}

/**
 * Map a failed write to a fixed message. The upstream error is only inspected, never returned:
 * it can carry the server's response.
 */
export function writeFailure(error: unknown): AkbError {
  if (error instanceof AkbError) {
    return error;
  }
  // The upstream API client throws an ErrorResponse, which is not an Error: it carries a
  // message and a status. Reading `message` is what lets a conflict be told from a failure.
  const shape = (error ?? {}) as { message?: unknown; statusCode?: unknown };
  const text = typeof shape.message === "string" ? shape.message : "";
  if (shape.statusCode === 409 || /out of date|conflict/i.test(text)) {
    return new AkbError("WRITE_CONFLICT", "The item changed elsewhere; run the command again.", 8);
  }
  return new AkbError("WRITE_FAILED", "The vault did not accept the change.", 8);
}
