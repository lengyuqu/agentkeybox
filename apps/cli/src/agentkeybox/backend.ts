import { filter, firstValueFrom, timeout } from "rxjs";

import { AuthenticationStatus } from "@bitwarden/common/auth/enums/authentication-status";
import { Fido2AlgorithmIdentifier } from "@bitwarden/common/platform/abstractions/fido2/fido2-authenticator.service.abstraction";
import { parseCredentialId } from "@bitwarden/common/platform/services/fido2/credential-id-utils";
import { isValidRpId } from "@bitwarden/common/platform/services/fido2/domain-utils";
import { Fido2AuthenticatorService } from "@bitwarden/common/platform/services/fido2/fido2-authenticator.service";
import { UserId } from "@bitwarden/common/types/guid";
import { CipherRepromptType, CipherType } from "@bitwarden/common/vault/enums";
import { Cipher } from "@bitwarden/common/vault/models/domain/cipher";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { ENCRYPTED_CIPHERS } from "@bitwarden/common/vault/services/key-state/ciphers.state";

import { LockCommand } from "../auth/commands/lock.command";
import { LoginCommand } from "../auth/commands/login.command";
import { UnlockCommand } from "../key-management/commands/unlock.command";
import { ConfigCommand } from "../platform/commands/config.command";
import { ServiceContainer } from "../service-container/service-container";

import { AuditRecord, auditField, AuditSink, auditSelector, AuditTarget, noAudit } from "./audit";
import {
  assertionReply,
  clientData,
  FixedCredentialInterface,
  parsePasskeyRegistration,
  parsePasskeyRequest,
  PasskeyRegistration,
  PasskeyRequest,
  registrationReply,
} from "./passkey";
import { deadline, defaultPolicy, SessionPolicy } from "./policy";
import {
  AkbError,
  credentialValue,
  metadata,
  normalizeUrl,
  parseSecretSpecsPayload,
  reference,
  Request,
  resolveSecrets,
  selectItem,
  TotpCode,
  TotpGenerator,
  VAULT_ACCESS,
  VAULT_WRITES,
} from "./protocol";
import { requireActiveScreen, screenState } from "./screen";
import {
  applyField,
  assertEditable,
  assertReferenceFree,
  FieldChange,
  NewLogin,
  newLoginView,
  parseExactRef,
  parseFieldChange,
  parseNewLogin,
  writeFailure,
} from "./write";

/** Operations that hand out or change a credential. Discovery (list, show) is not recorded. */
const AUDITED: readonly string[] = [
  "get",
  "resolve",
  "create",
  "set",
  "delete",
  "restore",
  "assert",
  "register",
];

/** One instance per process/profile: upstream secure storage uses process.env.BW_SESSION. */
export class Backend {
  private unlockedAt = 0;
  private accessedAt = 0;
  private audit: AuditSink = noAudit;

  constructor(
    private readonly services: ServiceContainer,
    private idleMs: number | null = defaultPolicy.idle_ms,
    private maxMs: number | null = defaultPolicy.max_ms,
    private readonly readScreen = screenState,
  ) {}

  /** TOTP codes come from the upstream SDK; AKB only handles timing. */
  private readonly totp: TotpGenerator = async (seed, minValidSeconds) => {
    const generate = async (): Promise<TotpCode | undefined> => {
      // Take the time first: the code belongs to the window that was current when it was made.
      const now = Math.floor(Date.now() / 1000);
      try {
        const { code, period } = await firstValueFrom(this.services.totpService.getCode$(seed));
        const length = period > 0 ? period : 30;
        return { code, expiresIn: length - (now % length) };
      } catch {
        return undefined;
      }
    };
    let result = await generate();
    if (result && result.expiresIn < minValidSeconds) {
      // A code about to expire may be rejected by the time the command uses it.
      await new Promise((resolve) => setTimeout(resolve, result.expiresIn * 1000 + 250));
      result = await generate();
    }
    return result;
  };

  /** The synced vault as decrypted views, read only after a successful online sync. */
  private async loadItems(userId: UserId, trashed = false): Promise<CipherView[]> {
    const s = this.services;
    // Do not use getAllDecrypted's list cache: it can return [] on SDK errors,
    // which would misreport decryption failures as missing accounts. Decrypt the
    // freshly synced encrypted records explicitly using upstream crypto instead.
    // fullSync clears the state to null before replacing it. Lowdb's update
    // observable can lag behind the completed write; getAll maps that null to {},
    // causing intermittent false NOT_FOUND results in a long-lived process.
    const encrypted = await firstValueFrom(
      s.stateProvider.getUser(userId, ENCRYPTED_CIPHERS).state$.pipe(
        filter((value) => value != null),
        timeout(5000),
      ),
    ).catch(() => {
      throw new AkbError("SYNC_STATE_TIMEOUT", "Synced vault state is not ready.", 8);
    });
    requireActiveScreen(await this.readScreen());
    const records = Object.values(encrypted)
      .map((data) => new Cipher(data))
      .filter((item) => (item.deletedDate != null) === trashed && !item.isPartial);
    const items: CipherView[] = [];
    try {
      for (const record of records) {
        items.push(await s.cipherService.decrypt(record, userId));
      }
    } catch {
      throw new AkbError(
        "DECRYPT_FAILED",
        "Unable to decrypt vault records; no credentials returned.",
      );
    }
    return items;
  }

  /** Generated secrets are made here and returned to nobody: they are only stored. */
  private generatePassword(length: number): Promise<string> {
    return this.services.passwordGenerationService.generatePassword({
      type: "password",
      length,
      uppercase: true,
      lowercase: true,
      number: true,
      special: true,
      minNumber: 1,
      minSpecial: 1,
    });
  }

  private async create(items: CipherView[], login: NewLogin, userId: UserId): Promise<unknown> {
    assertReferenceFree(items, login.ref);
    const password = login.generate
      ? await this.generatePassword(login.length)
      : (login.password as string);
    try {
      const created = await this.services.cipherService.createWithServer(
        newLoginView(login, password),
        userId,
      );
      if (!created?.id) {
        throw new Error("No item was returned");
      }
      // The reply describes the item. It never contains the password, generated or given.
      return { ...metadata(created), created: true };
    } catch (error) {
      throw writeFailure(error);
    }
  }

  private async set(items: CipherView[], change: FieldChange, userId: UserId): Promise<unknown> {
    // Reject a seed that cannot produce codes now, rather than store one that never works.
    if (change.field === "totp" && !(await this.totp((change.value ?? "").trim(), 0))) {
      throw new AkbError("INVALID_TOTP", "The one-time code seed is not valid.", 2);
    }
    // Made once, so a retry after a conflict stores the same value.
    const value = change.generate
      ? await this.generatePassword(change.length)
      : (change.value as string);
    let current = items;
    for (let attempt = 0; ; attempt++) {
      const found = selectItem(current, change.ref);
      const view = current.find((item) => item.id === found.id) as CipherView;
      applyField(view, change.field, value);
      try {
        const updated = await this.services.cipherService.updateWithServer(view, userId);
        if (!updated?.id) {
          throw new Error("No item was returned");
        }
        return metadata(updated);
      } catch (error) {
        const failure = writeFailure(error);
        // Setting a field is idempotent, so one retry on fresh data is safe.
        if (failure.code !== "WRITE_CONFLICT" || attempt > 0) {
          throw failure;
        }
        current = await this.loadItems(userId);
      }
    }
  }

  /**
   * Sign a site's challenge with a login's passkey. The upstream authenticator does the
   * signing and keeps the counter; the private key never leaves the vault.
   */
  private async assertPasskey(
    items: CipherView[],
    request: PasskeyRequest,
    userId: UserId,
    target: AuditTarget,
  ): Promise<unknown> {
    const view = items.find((item) => item.id === selectItem(items, request.ref).id) as CipherView;
    target.id = view.id;
    const credential =
      view.type === CipherType.Login ? view.login?.fido2Credentials?.[0] : undefined;
    if (!credential) {
      throw new AkbError("FIELD_NOT_FOUND", "This item has no passkey.", 5);
    }
    // Re-entering the master password is a person's check; nothing here can pass it.
    if (view.reprompt !== CipherRepromptType.None) {
      throw new AkbError(
        "PERMISSION_DENIED",
        "This item asks for the master password each time; use it in an official client.",
        7,
      );
    }
    if (!(await isValidRpId(credential.rpId, request.origin))) {
      throw new AkbError("INVALID_ORIGIN", "This passkey is not for that site.", 2);
    }
    const { json, hash } = clientData(request.origin, request.challenge);
    const s = this.services;
    const authenticator = new Fido2AuthenticatorService<void>(
      s.cipherService,
      new FixedCredentialInterface(view.id),
      s.syncService,
      s.accountService,
    );
    let signed;
    try {
      signed = await authenticator.getAssertion(
        {
          rpId: credential.rpId,
          hash,
          // Naming the credential keeps the authenticator from picking a different login.
          allowCredentialDescriptorList: [
            { id: parseCredentialId(credential.credentialId), type: "public-key" },
          ],
          // AKB does not verify a person, so it never claims to have. A site that requires
          // verification will refuse the response.
          requireUserVerification: false,
          extensions: {},
          fallbackSupported: false,
          assumeUserPresence: true,
        },
        undefined,
      );
    } catch (error) {
      throw error instanceof AkbError
        ? error
        : new AkbError("PASSKEY_FAILED", "The passkey could not sign the challenge.", 8);
    }
    return assertionReply(signed, json, credential.rpId);
  }

  /**
   * Create a passkey for a site and store it in an existing login. The upstream authenticator
   * makes the key and saves it with the login; only the public answer leaves this process.
   * A login that already has a passkey is never overwritten: that would lock its owner out of
   * the site if the new one is not completed there.
   */
  private async registerPasskey(
    items: CipherView[],
    request: PasskeyRegistration,
    userId: UserId,
    target: AuditTarget,
  ): Promise<unknown> {
    const view = items.find((item) => item.id === selectItem(items, request.ref).id) as CipherView;
    target.id = view.id;
    if (view.type !== CipherType.Login || !view.login) {
      throw new AkbError("UNSUPPORTED_FIELD", "A passkey can only be added to a login.", 10);
    }
    assertEditable(view);
    if (view.reprompt !== CipherRepromptType.None) {
      throw new AkbError(
        "PERMISSION_DENIED",
        "This item asks for the master password each time; use it in an official client.",
        7,
      );
    }
    if (view.login.fido2Credentials?.length) {
      throw new AkbError("PASSKEY_EXISTS", "This login already has a passkey.", 6);
    }
    const rpId = request.rpId ?? new URL(request.origin).hostname;
    if (!(await isValidRpId(rpId, request.origin))) {
      throw new AkbError("INVALID_ORIGIN", "That site id is not valid for this origin.", 2);
    }
    const { json, hash } = clientData(request.origin, request.challenge, "webauthn.create");
    const s = this.services;
    const authenticator = new Fido2AuthenticatorService<void>(
      s.cipherService,
      new FixedCredentialInterface(view.id),
      s.syncService,
      s.accountService,
    );
    let made;
    try {
      made = await authenticator.makeCredential(
        {
          hash,
          rpEntity: { id: rpId, name: request.rpName ?? rpId },
          userEntity: {
            id: new Uint8Array(Buffer.from(request.userId, "base64url")),
            name: request.userName,
            displayName: request.displayName,
          },
          credTypesAndPubKeyAlgs: [{ alg: Fido2AlgorithmIdentifier.ES256, type: "public-key" }],
          excludeCredentialDescriptorList: [],
          extensions: {},
          // A passkey: one the site can find without being told which account it is for.
          requireResidentKey: true,
          // AKB does not verify a person, so it never claims to have.
          requireUserVerification: false,
          fallbackSupported: false,
        },
        undefined,
      );
    } catch (error) {
      throw error instanceof AkbError
        ? error
        : new AkbError("PASSKEY_FAILED", "The passkey could not be created.", 8);
    }
    return registrationReply(made, json, rpId);
  }

  /**
   * Bring a deleted login back from the trash. `items` are the live ones: a reference that
   * has been used again since the delete must not end up on two logins.
   */
  private async restore(items: CipherView[], ref: string, userId: UserId): Promise<unknown> {
    const trashed = await this.loadItems(userId, true);
    const found = selectItem(trashed, ref, true);
    const view = trashed.find((candidate) => candidate.id === found.id) as CipherView;
    assertEditable(view);
    const name = reference(view);
    if (name !== undefined) {
      assertReferenceFree(items, name);
    }
    try {
      await this.services.cipherService.restoreWithServer(view.id, userId);
    } catch (error) {
      throw writeFailure(error);
    }
    return { ...metadata(view), restored: true };
  }

  /**
   * Move a login to the trash. It is not destroyed: the vault keeps it, and its owner can
   * restore it from any official client. Its reference is free to use again straight away.
   */
  private async remove(items: CipherView[], ref: string, userId: UserId): Promise<unknown> {
    const item = selectItem(items, ref);
    const view = items.find((candidate) => candidate.id === item.id) as CipherView;
    assertEditable(view);
    try {
      await this.services.cipherService.softDeleteWithServer(view.id, userId);
    } catch (error) {
      throw writeFailure(error);
    }
    return { ...metadata(view), deleted: true };
  }

  setPolicy(policy: SessionPolicy) {
    this.idleMs = policy.idle_ms;
    this.maxMs = policy.max_ms;
  }

  private policy(): SessionPolicy {
    return { idle_ms: this.idleMs, max_ms: this.maxMs };
  }

  async expire() {
    const end = deadline(this.unlockedAt, this.accessedAt, this.policy());
    if (end !== null && Date.now() >= end) {
      await this.lock();
    }
  }

  private async lock() {
    const s = this.services;
    if (await firstValueFrom(s.accountService.activeAccount$)) {
      await new LockCommand(s.lockService, s.accountService).run();
    }
    delete process.env.BW_SESSION;
    this.unlockedAt = this.accessedAt = 0;
  }

  private async status() {
    const s = this.services;
    const state = await s.authService.getAuthStatus();
    const account = await firstValueFrom(s.accountService.activeAccount$);
    const env = await firstValueFrom(s.environmentService.environment$);
    const screen = await this.readScreen();
    const screenBlocksAccess = screen === "locked" || screen === "unavailable";
    return {
      status:
        state === AuthenticationStatus.Unlocked && screenBlocksAccess
          ? "locked"
          : ["unauthenticated", "locked", "unlocked"][state],
      screen_state: screen,
      lock_reason:
        state === AuthenticationStatus.LoggedOut
          ? null
          : screen === "unavailable"
            ? "screen_state_unavailable"
            : screen === "locked"
              ? "screen_locked"
              : state === AuthenticationStatus.Locked
                ? "vault_locked"
                : null,
      server: env.getUrls().base,
      email: account?.email,
      last_sync_at: await s.syncService.getLastSync(),
      session_policy: this.policy(),
      expires_at:
        deadline(this.unlockedAt, this.accessedAt, this.policy()) === null
          ? null
          : new Date(deadline(this.unlockedAt, this.accessedAt, this.policy())).toISOString(),
    };
  }

  async dispatch(request: Request): Promise<unknown> {
    await this.expire();
    const s = this.services;
    const a = request.args ?? {};
    const state = await s.authService.getAuthStatus();
    switch (request.operation) {
      case "status":
        return this.status();
      case "configure": {
        if (state !== AuthenticationStatus.LoggedOut) {
          throw new AkbError("LOGOUT_REQUIRED", "Log out before changing servers.", 3);
        }
        let url: URL;
        try {
          url = new URL(a.server);
        } catch {
          throw new AkbError("INVALID_SERVER", "A valid HTTPS server URL is required.", 2);
        }
        if (url.username || url.password || url.search || url.hash || url.protocol !== "https:") {
          throw new AkbError(
            "INVALID_SERVER",
            "Use HTTPS; the upstream SDK requires TLS even for loopback servers.",
            2,
          );
        }
        const result = await new ConfigCommand(s.environmentService, s.accountService).run(
          "server",
          url.toString().replace(/\/$/, ""),
          {},
        );
        if (!result.success) {
          throw new AkbError("CONFIG_FAILED", "Server configuration failed.");
        }
        return this.status();
      }
      case "login": {
        if (state !== AuthenticationStatus.LoggedOut) {
          throw new AkbError("ALREADY_LOGGED_IN", "Use auth unlock or auth logout.", 3);
        }
        const environment = await firstValueFrom(s.environmentService.environment$);
        if (!environment.getUrls().base) {
          throw new AkbError("NOT_CONFIGURED", "Run akb config server <url> first.", 2);
        }
        if (!a.email || !a.password) {
          throw new AkbError("INPUT_REQUIRED", "Email and password are required.", 2);
        }
        requireActiveScreen(await this.readScreen());
        const command = new LoginCommand(
          s.loginStrategyService,
          s.authService,
          s.twoFactorApiService,
          s.cryptoFunctionService,
          s.environmentService,
          s.passwordGenerationService,
          s.platformUtilsService,
          s.accountService,
          s.twoFactorService,
          s.syncService,
          s.keyConnectorService,
          () => s.logout(),
          s.ssoUrlService,
          s.i18nService,
          s.masterPasswordService,
          s.userDecryptionOptionsService,
          s.encryptedMigrator,
        );
        const result = await command.run(a.email, a.password, {
          method: a.method,
          code: a.code,
        });
        // Login responses contain the session key. Never forward them or upstream errors.
        if (!result.success) {
          if (await firstValueFrom(s.accountService.activeAccount$)) {
            await s.logout();
          }
          delete process.env.BW_SESSION;
          throw new AkbError(
            "LOGIN_FAILED",
            "Login failed; check credentials, network and 2FA requirements.",
            3,
          );
        }
        if ((await s.authService.getAuthStatus()) === AuthenticationStatus.Unlocked) {
          this.unlockedAt = this.accessedAt = Date.now();
        }
        return this.status();
      }
      case "unlock": {
        if (state === AuthenticationStatus.LoggedOut) {
          throw new AkbError("AUTH_REQUIRED", "Run akb auth login.", 3);
        }
        requireActiveScreen(await this.readScreen());
        if (state === AuthenticationStatus.Unlocked) {
          return this.status();
        }
        if (!a.password) {
          throw new AkbError("INPUT_REQUIRED", "Password is required.", 2);
        }
        const command = new UnlockCommand(
          s.accountService,
          s.logService,
          s.keyConnectorService,
          s.environmentService,
          s.organizationApiService,
          () => s.logout(),
          s.i18nService,
          s.encryptedMigrator,
          s.unlockService,
          s.biometricsService,
        );
        const result = await command.run(a.password, {}).catch(async () => {
          // Migrations can fail after the user key was installed. Never leave an
          // unlocked service without a session deadline after such a failure.
          await this.lock();
          throw new AkbError("UNLOCK_FAILED", "Unlock or post-unlock migration failed.", 4);
        });
        if (!result.success) {
          await this.lock();
          throw new AkbError("UNLOCK_FAILED", "Unable to unlock with the supplied password.", 4);
        }
        this.unlockedAt = this.accessedAt = Date.now();
        return this.status();
      }
      case "lock":
        await this.lock();
        return this.status();
      case "logout":
        if (await firstValueFrom(s.accountService.activeAccount$)) {
          await s.logout();
        }
        delete process.env.BW_SESSION;
        this.unlockedAt = this.accessedAt = 0;
        return this.status();
    }
    if (!VAULT_ACCESS.includes(request.operation)) {
      throw new AkbError("INVALID_OPERATION", "Unsupported operation.", 2);
    }
    if (!AUDITED.includes(request.operation)) {
      return this.access(request, state, []);
    }
    const targets: AuditTarget[] = [];
    let result: unknown;
    try {
      result = await this.access(request, state, targets);
    } catch (error) {
      this.record({
        op: request.operation,
        outcome: "error",
        code: error instanceof AkbError ? error.code : "INTERNAL_ERROR",
        targets,
      });
      throw error;
    }
    const recorded = this.record({ op: request.operation, outcome: "ok", targets });
    if (recorded) {
      return result;
    }
    if (VAULT_WRITES.includes(request.operation)) {
      // The change is already stored. Report it, and say the record is missing.
      return { ...(result as object), audit_failed: true };
    }
    // Nothing has been handed out yet, so an access that cannot be recorded is withheld.
    throw new AkbError("AUDIT_FAILED", "The access could not be recorded; no value returned.", 10);
  }

  setAudit(sink: AuditSink) {
    this.audit = sink;
  }

  /** Returns false when the record could not be written. */
  private record(entry: AuditRecord): boolean {
    try {
      this.audit(entry);
      return true;
    } catch {
      return false;
    }
  }

  private async access(
    request: Request,
    state: AuthenticationStatus,
    targets: AuditTarget[],
  ): Promise<unknown> {
    const s = this.services;
    const a = request.args ?? {};
    // Reject malformed requests before spending a network sync on them.
    const secretSpecs =
      request.operation === "resolve" ? parseSecretSpecsPayload(a.specs) : undefined;
    const url = request.operation === "list" ? normalizeUrl(a.url) : undefined;
    const trashed = request.operation === "list" && a.trashed === "1";
    if (trashed && url) {
      throw new AkbError("INVALID_ARGUMENT", "Use --trashed with --search, not with --url.", 2);
    }
    const newLogin = request.operation === "create" ? parseNewLogin(a) : undefined;
    const change = request.operation === "set" ? parseFieldChange(a) : undefined;
    const doomed = request.operation === "delete" ? parseExactRef(a.ref) : undefined;
    const revived = request.operation === "restore" ? parseExactRef(a.ref) : undefined;
    const passkey = request.operation === "assert" ? parsePasskeyRequest(a) : undefined;
    const registration = request.operation === "register" ? parsePasskeyRegistration(a) : undefined;
    if (doomed || revived) {
      targets.push({ ref: auditSelector((doomed ?? revived) as string) });
    } else if (passkey || registration) {
      const asked = (passkey ?? registration) as PasskeyRequest;
      targets.push({ ref: auditSelector(asked.ref), field: "passkey", origin: asked.origin });
    } else if (secretSpecs) {
      targets.push(
        ...secretSpecs.map((spec) => ({
          env: spec.name,
          ref: auditSelector(spec.ref),
          field: auditField(spec.field),
        })),
      );
    } else if (newLogin) {
      targets.push({ ref: auditSelector(`ref:${newLogin.ref}`), field: "password" });
    } else if (change) {
      targets.push({ ref: auditSelector(change.ref), field: auditField(change.field) });
    } else if (request.operation === "get") {
      targets.push({ ref: auditSelector(a.ref), field: auditField(a.field) });
    }
    if (state === AuthenticationStatus.LoggedOut) {
      throw new AkbError("AUTH_REQUIRED", "Run akb auth login.", 3);
    }
    requireActiveScreen(await this.readScreen());
    if (state !== AuthenticationStatus.Unlocked) {
      throw new AkbError("VAULT_LOCKED", "Run akb auth unlock in your terminal.", 4);
    }
    // MVP deliberately requires a fresh successful online sync for all vault reads.
    try {
      if (!(await s.syncService.fullSync(true, true))) {
        throw new Error("Incomplete sync");
      }
    } catch {
      throw new AkbError(
        "SYNC_FAILED",
        "Online sync failed; cached credentials were not returned.",
        8,
      );
    }
    if (request.operation === "sync") {
      requireActiveScreen(await this.readScreen());
      this.accessedAt = Date.now();
      return this.status();
    }
    const account = await firstValueFrom(s.accountService.activeAccount$);
    if (!account) {
      throw new AkbError("AUTH_REQUIRED", "Log in again.", 3);
    }
    const items = await this.loadItems(account.id, trashed);
    let result: unknown;
    if (request.operation === "list") {
      // Upstream's matcher applies the vault's equivalent-domain and URI match rules. It is
      // given our explicitly decrypted items rather than its list cache (see above).
      const matched = url ? await s.cipherService.filterCiphersForUrl(items, url) : items;
      result = matched
        .map((item) => ({
          ...metadata(item),
          ...(trashed ? { deleted_at: new Date(item.deletedDate as Date).toISOString() } : {}),
        }))
        .filter(
          (item) =>
            !a.search ||
            [item.name, item.ref, item.username].some((v) =>
              v?.toLowerCase().includes(a.search.toLowerCase()),
            ),
        );
    } else if (doomed) {
      result = await this.remove(items, doomed, account.id);
      targets[0].id = (result as { id: string }).id;
    } else if (revived) {
      result = await this.restore(items, revived, account.id);
      targets[0].id = (result as { id: string }).id;
    } else if (passkey) {
      result = await this.assertPasskey(items, passkey, account.id, targets[0]);
    } else if (registration) {
      result = await this.registerPasskey(items, registration, account.id, targets[0]);
    } else if (secretSpecs) {
      result = { values: await resolveSecrets(items, secretSpecs, this.totp) };
      secretSpecs.forEach((spec, index) => {
        targets[index].id = selectItem(items, spec.ref).id;
      });
    } else if (newLogin) {
      result = await this.create(items, newLogin, account.id);
      targets[0].id = (result as { id: string }).id;
    } else if (change) {
      result = await this.set(items, change, account.id);
      targets[0].id = (result as { id: string }).id;
    } else {
      const item = selectItem(items, a.ref);
      if (targets[0]) {
        targets[0].id = item.id;
      }
      if (request.operation === "show") {
        result = metadata(item);
      } else {
        const read = await credentialValue(item, a.field, this.totp, 0);
        result = {
          id: item.id,
          field: a.field,
          value: read.value,
          ...(read.expiresIn === undefined ? {} : { expires_in: read.expiresIn }),
        };
      }
    }
    // The Mac can lock while the network request or decryption is in flight.
    requireActiveScreen(await this.readScreen());
    this.accessedAt = Date.now();
    return result;
  }
}
