export class AkbError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly exitCode = 1,
  ) {
    super(message);
  }
}

export interface Request {
  operation: string;
  args?: Record<string, string>;
}

export interface Reply {
  schema_version: 1;
  ok: boolean;
  data?: unknown;
  error?: { code: string; message: string; exit_code: number };
}

export function failure(error: unknown): Reply {
  const known = error instanceof AkbError;
  return {
    schema_version: 1,
    ok: false,
    error: {
      code: known ? error.code : "INTERNAL_ERROR",
      message: known ? error.message : "Operation failed; no upstream payload was logged.",
      exit_code: known ? error.exitCode : 1,
    },
  };
}

/** A deliberately narrow view: never serialize an upstream CipherView wholesale. */
export interface Item {
  id: string;
  name?: string;
  type?: number;
  isDeleted?: boolean;
  deletedDate?: unknown;
  viewPassword?: boolean;
  login?: {
    username?: string;
    password?: string;
    totp?: string;
    uris?: { uri?: string }[];
    fido2Credentials?: { rpId?: string }[];
  };
  notes?: string;
  sshKey?: { privateKey?: string; publicKey?: string; keyFingerprint?: string };
  fields?: { name?: string; value?: string; type?: number }[];
}

export function reference(item: Item): string | undefined {
  return item.fields?.find((field) => field.name === "agentkeybox.ref")?.value;
}

/** Accept an address or a bare domain. Returns undefined when none was given. */
export function normalizeUrl(input: string | undefined): string | undefined {
  if (input === undefined) {
    return undefined;
  }
  const value = input.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;
  let valid = value.length > 0 && value.length <= 2048;
  try {
    valid = valid && new URL(withScheme).host !== "";
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new AkbError("INVALID_URL", "Provide a valid URL or domain.", 2);
  }
  return withScheme;
}

/**
 * Where a login is used, reduced to scheme and host. Addresses can carry tokens in the path
 * or query, so discovery output never includes more than the origin.
 */
export function origins(item: Item): string[] {
  const found = new Set<string>();
  for (const { uri } of item.login?.uris ?? []) {
    try {
      const url = new URL(uri ?? "");
      if (url.host) {
        found.add(`${url.protocol}//${url.host}`);
      }
    } catch {
      // Not an address (for example a plain domain-less value); nothing safe to show.
    }
  }
  return [...found];
}

export function metadata(item: Item) {
  return {
    id: item.id,
    ref: reference(item),
    name: item.name,
    type: item.type,
    username: item.login?.username,
    uris: origins(item),
    // Which sites a passkey is for. The key itself is never shown; `passkey assert` signs with it.
    passkey_rp_ids: (item.login?.fido2Credentials ?? []).flatMap((c) => (c.rpId ? [c.rpId] : [])),
    credential_fields: [
      ...(item.login?.password != null ? ["password"] : []),
      ...(item.login?.fido2Credentials?.length ? ["passkey"] : []),
      ...(item.login?.totp?.trim() ? ["totp"] : []),
      ...(item.notes != null ? ["notes"] : []),
      ...(item.sshKey?.privateKey != null ? ["private_key", "public_key"] : []),
      ...(item.fields ?? [])
        .filter((f) => f.name && !f.name.startsWith("agentkeybox."))
        .map((f) => `custom:${f.name}`),
    ],
  };
}

/** Find one item by exact reference. `trashed` looks among deleted items instead of live ones. */
export function selectItem(items: Item[], ref: string, trashed = false): Item {
  if (!ref?.startsWith("id:") && !ref?.startsWith("ref:")) {
    throw new AkbError("INVALID_REFERENCE", "Use id:<uuid> or ref:<exact-reference>.", 2);
  }
  const matches = items.filter(
    (item) =>
      (!!item.isDeleted || !!item.deletedDate) === trashed &&
      (ref.startsWith("id:") ? item.id === ref.slice(3) : reference(item) === ref.slice(4)),
  );
  if (!matches.length) {
    throw new AkbError("NOT_FOUND", "Account not found.", 5);
  }
  if (matches.length !== 1) {
    throw new AkbError("AMBIGUOUS_MATCH", "Reference is not unique; use id:<uuid>.", 6);
  }
  return matches[0];
}

/** Operations that read vault contents. They need a fresh sync and an active desktop. */
export const VAULT_READS: readonly string[] = ["sync", "list", "show", "get", "resolve", "assert"];
/** Operations that change vault contents. They also need a fresh sync and an active desktop. */
export const VAULT_WRITES: readonly string[] = ["create", "set", "delete", "restore", "register"];
export const VAULT_ACCESS: readonly string[] = [...VAULT_READS, ...VAULT_WRITES];

export interface SecretSpec {
  name: string;
  ref: string;
  field: string;
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SECRET_FIELD = /^(password|username|notes|private_key|public_key|totp|custom:.+)$/;

/**
 * Parse `NAME=<ref>[#<field>]`. The field defaults to `password`. A trailing `#suffix` is
 * treated as the field only when it is a valid field name, so references containing `#`
 * keep working. Error text never repeats the input.
 */
export function parseSecretSpec(spec: string): SecretSpec {
  const eq = spec.indexOf("=");
  const name = eq > 0 ? spec.slice(0, eq) : "";
  let ref = eq > 0 ? spec.slice(eq + 1) : "";
  if (!ENV_NAME.test(name) || !ref) {
    throw new AkbError(
      "INVALID_SECRET_SPEC",
      "Use NAME=ref:<name>[#field] or NAME=id:<uuid>[#field].",
      2,
    );
  }
  let field = "password";
  const hash = ref.lastIndexOf("#");
  if (hash > 0 && SECRET_FIELD.test(ref.slice(hash + 1))) {
    field = ref.slice(hash + 1);
    ref = ref.slice(0, hash);
  }
  return { name, ref, field };
}

function validateSecretSpecs(specs: SecretSpec[]): SecretSpec[] {
  if (specs.length === 0) {
    throw new AkbError("INPUT_REQUIRED", "Specify at least one --env NAME=<ref>.", 2);
  }
  if (
    specs.some((spec) => !ENV_NAME.test(spec.name) || !spec.ref || !SECRET_FIELD.test(spec.field))
  ) {
    throw new AkbError("INVALID_SECRET_SPEC", "Invalid secret specification.", 2);
  }
  // Windows environment names are case-insensitive, so compare them that way everywhere.
  if (new Set(specs.map((spec) => spec.name.toUpperCase())).size !== specs.length) {
    throw new AkbError("INVALID_SECRET_SPEC", "Each environment variable may be set once.", 2);
  }
  return specs;
}

export function parseSecretSpecs(specs: string[]): SecretSpec[] {
  return validateSecretSpecs(specs.map(parseSecretSpec));
}

/** Validate specs that arrive over the local service socket as a JSON string. */
export function parseSecretSpecsPayload(payload: string | undefined): SecretSpec[] {
  let value: unknown;
  try {
    value = JSON.parse(payload ?? "");
  } catch {
    value = undefined;
  }
  if (
    !Array.isArray(value) ||
    value.length > 64 ||
    value.some(
      (spec) =>
        !spec ||
        typeof spec !== "object" ||
        typeof spec.name !== "string" ||
        typeof spec.ref !== "string" ||
        typeof spec.field !== "string",
    )
  ) {
    throw new AkbError("INVALID_REQUEST", "Invalid secret specifications.", 2);
  }
  // Rebuild each spec so unexpected extra properties never travel any further.
  return validateSecretSpecs(
    value.map((spec: SecretSpec) => ({ name: spec.name, ref: spec.ref, field: spec.field })),
  );
}

export interface TotpCode {
  code: string;
  /** Whole seconds until the code stops being valid. */
  expiresIn: number;
}

/**
 * Produce a one-time code for a TOTP seed. `minValidSeconds` lets the caller ask for a code that
 * will stay valid for at least that long (the generator waits for the next window if needed).
 */
export type TotpGenerator = (
  seed: string,
  minValidSeconds: number,
) => Promise<TotpCode | undefined>;

/** Read one field. Unlike `credential`, this can also produce a TOTP code. */
export async function credentialValue(
  item: Item,
  field: string,
  totp?: TotpGenerator,
  minValidSeconds = 0,
): Promise<{ value: string; expiresIn?: number }> {
  if (field !== "totp") {
    return { value: credential(item, field) };
  }
  if (item.viewPassword === false) {
    throw new AkbError("PERMISSION_DENIED", "Credential visibility is restricted.", 7);
  }
  const seed = item.login?.totp;
  if (!seed?.trim()) {
    throw new AkbError("FIELD_NOT_FOUND", "Credential field not found.", 5);
  }
  const generated = totp ? await totp(seed, minValidSeconds) : undefined;
  if (!generated?.code) {
    // The seed is a secret; never include it, or the upstream error, in the message.
    throw new AkbError("TOTP_FAILED", "Could not generate a one-time code.");
  }
  return { value: generated.code, expiresIn: generated.expiresIn };
}

/** Resolve every spec or none: a missing item must not yield a half-injected command. */
export async function resolveSecrets(
  items: Item[],
  specs: SecretSpec[],
  totp?: TotpGenerator,
  minTotpSeconds = 3,
): Promise<Record<string, string>> {
  const values: Record<string, string> = {};
  for (const spec of specs) {
    const item = selectItem(items, spec.ref);
    values[spec.name] = (await credentialValue(item, spec.field, totp, minTotpSeconds)).value;
  }
  return values;
}

export function credential(item: Item, field: string): string {
  if (item.viewPassword === false) {
    throw new AkbError("PERMISSION_DENIED", "Credential visibility is restricted.", 7);
  }
  let value: string | undefined;
  switch (field) {
    case "password":
      value = item.login?.password;
      break;
    case "username":
      value = item.login?.username;
      break;
    case "notes":
      value = item.notes;
      break;
    case "private_key":
      value = item.sshKey?.privateKey;
      break;
    case "public_key":
      value = item.sshKey?.publicKey;
      break;
    default: {
      if (!field?.startsWith("custom:")) {
        throw new AkbError("INVALID_FIELD", "Use a built-in field or custom:<name>.", 2);
      }
      const fields = (item.fields ?? []).filter((f) => f.name === field.slice(7));
      if (fields.length > 1) {
        throw new AkbError("AMBIGUOUS_FIELD", "Custom field name is not unique.", 6);
      }
      if (fields[0]?.type === 3) {
        throw new AkbError("UNSUPPORTED_FIELD", "Linked fields are not supported in this MVP.", 10);
      }
      value = fields[0]?.value;
    }
  }
  if (value == null) {
    throw new AkbError("FIELD_NOT_FOUND", "Credential field not found.", 5);
  }
  return value;
}
