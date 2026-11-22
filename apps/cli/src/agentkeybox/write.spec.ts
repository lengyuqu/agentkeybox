import { ErrorResponse } from "@bitwarden/common/models/response/error.response";
import { CipherType, FieldType } from "@bitwarden/common/vault/enums";

import { AkbError } from "./protocol";
import {
  applyField,
  assertEditable,
  assertReferenceFree,
  newLoginView,
  parseExactRef,
  parseFieldChange,
  parseNewLogin,
  isTotpSeed,
  parseReferenceName,
  writeFailure,
} from "./write";

const base = { name: "GitHub", ref: "github/ci", generate: "1" };

/** Like an item read back from the vault: the server marks the owner's own items as editable. */
function login() {
  const view = newLoginView(
    parseNewLogin({
      ...base,
      generate: undefined as unknown as string,
      password: "old-pw",
      username: "me",
      urls: JSON.stringify(["https://github.com/login"]),
    }),
    "old-pw",
  );
  view.edit = true;
  return view;
}

describe("parseNewLogin", () => {
  it("accepts a generated password", () => {
    expect(parseNewLogin(base)).toMatchObject({
      name: "GitHub",
      ref: "github/ci",
      generate: true,
      length: 24,
      urls: [],
    });
  });

  it("accepts a password given on standard input", () => {
    const parsed = parseNewLogin({ name: "x", ref: "r", password: "given-pw" });
    expect(parsed).toMatchObject({ generate: false, password: "given-pw" });
  });

  it("requires exactly one source for the password", () => {
    expect(() => parseNewLogin({ name: "x", ref: "r" })).toThrow("password");
    expect(() => parseNewLogin({ name: "x", ref: "r", password: "p", generate: "1" })).toThrow(
      "password",
    );
  });

  it("completes bare domains and rejects bad addresses", () => {
    expect(parseNewLogin({ ...base, urls: JSON.stringify(["github.com"]) }).urls).toEqual([
      "https://github.com",
    ]);
    expect(() => parseNewLogin({ ...base, urls: JSON.stringify(["http://"]) })).toThrow(
      "valid URL",
    );
    expect(() => parseNewLogin({ ...base, urls: "not json" })).toThrow("addresses");
    expect(() => parseNewLogin({ ...base, urls: JSON.stringify([1]) })).toThrow("addresses");
    expect(() =>
      parseNewLogin({ ...base, urls: JSON.stringify(Array(17).fill("https://a.test")) }),
    ).toThrow("addresses");
  });

  it("limits the generated password length", () => {
    expect(parseNewLogin({ ...base, length: "8" }).length).toBe(8);
    expect(parseNewLogin({ ...base, length: "128" }).length).toBe(128);
    for (const bad of ["7", "129", "abc", "12.5", ""]) {
      expect(() => parseNewLogin({ ...base, length: bad })).toThrow("length");
    }
  });

  it("requires a name and bounds sizes", () => {
    expect(() => parseNewLogin({ ...base, name: "  " })).toThrow("name");
    expect(() => parseNewLogin({ ...base, name: "x".repeat(201) })).toThrow("name");
    expect(() => parseNewLogin({ name: "x", ref: "r", password: "p".repeat(70_000) })).toThrow(
      "size limit",
    );
  });
});

describe("parseReferenceName", () => {
  it("accepts the name with or without the ref: prefix", () => {
    expect(parseReferenceName("github/ci")).toBe("github/ci");
    expect(parseReferenceName("ref:github/ci")).toBe("github/ci");
  });

  it("rejects empty, oversized and control-character names", () => {
    for (const bad of [undefined, "", "   ", "ref:", "x".repeat(201), "a\nb", "a\u0000b"]) {
      expect(() => parseReferenceName(bad)).toThrow("reference");
    }
  });
});

describe("parseFieldChange", () => {
  it("accepts the changeable fields", () => {
    for (const field of ["password", "username", "notes", "totp", "custom:api key"]) {
      const value = field === "totp" ? "JBSWY3DPEHPK3PXP" : "v";
      expect(parseFieldChange({ ref: "ref:x", field, value }).field).toBe(field);
    }
  });

  it("refuses fields it cannot change", () => {
    for (const field of ["private_key", "public_key", "custom:", "name", "", undefined]) {
      expect(() => parseFieldChange({ ref: "ref:x", field: field as string, value: "v" })).toThrow(
        "Use password",
      );
    }
  });

  it("keeps AgentKeybox's own fields out of reach", () => {
    expect(() =>
      parseFieldChange({ ref: "ref:x", field: "custom:agentkeybox.ref", value: "v" }),
    ).toThrow("managed by AgentKeybox");
  });

  it("generates only passwords, and needs exactly one source", () => {
    expect(parseFieldChange({ ref: "ref:x", field: "password", generate: "1" }).generate).toBe(
      true,
    );
    expect(() => parseFieldChange({ ref: "ref:x", field: "totp", generate: "1" })).toThrow(
      "Only the password",
    );
    expect(() => parseFieldChange({ ref: "ref:x", field: "password" })).toThrow("standard input");
    expect(() =>
      parseFieldChange({ ref: "ref:x", field: "password", value: "v", generate: "1" }),
    ).toThrow("standard input");
  });
});

describe("newLoginView", () => {
  it("builds an ordinary login with the reference and addresses", () => {
    const view = login();
    expect(view.type).toBe(CipherType.Login);
    expect(view.name).toBe("GitHub");
    expect(view.login.username).toBe("me");
    expect(view.login.password).toBe("old-pw");
    expect(view.login.uris.map((uri) => uri.uri)).toEqual(["https://github.com/login"]);
    expect(view.fields).toHaveLength(1);
    expect(view.fields[0]).toMatchObject({ name: "agentkeybox.ref", value: "github/ci" });
    expect(view.notes).toBeUndefined();
  });
});

describe("assertReferenceFree", () => {
  const item = { id: "1", fields: [{ name: "agentkeybox.ref", value: "github/ci" }] };

  it("rejects a reference that is already used", () => {
    expect(() => assertReferenceFree([item], "github/ci")).toThrow("already exists");
    expect(() => assertReferenceFree([item], "github/ci")).toThrow(
      expect.objectContaining({ code: "REF_EXISTS", exitCode: 6 }),
    );
  });

  it("allows a new reference and ignores deleted items", () => {
    expect(() => assertReferenceFree([item], "other")).not.toThrow();
    expect(() => assertReferenceFree([{ ...item, isDeleted: true }], "github/ci")).not.toThrow();
  });
});

describe("parseExactRef", () => {
  it("accepts only an exact reference", () => {
    expect(parseExactRef("ref:github/ci")).toBe("ref:github/ci");
    expect(parseExactRef("id:3f2a")).toBe("id:3f2a");
    for (const bad of [
      undefined,
      "",
      "github/ci",
      "ref:",
      "id:",
      "name:x",
      `ref:${"x".repeat(250)}`,
    ]) {
      expect(() => parseExactRef(bad)).toThrow(
        expect.objectContaining({ code: "INVALID_REFERENCE", exitCode: 2 }),
      );
    }
  });
});

describe("assertEditable", () => {
  it("refuses only items the server marked read-only", () => {
    expect(() => assertEditable({ edit: false })).toThrow(
      expect.objectContaining({ code: "PERMISSION_DENIED" }),
    );
    expect(() => assertEditable({ edit: true })).not.toThrow();
    expect(() => assertEditable({})).not.toThrow();
  });
});

describe("applyField", () => {
  it("changes only the requested field", () => {
    const view = login();
    applyField(view, "password", "new-pw");
    expect(view.login.password).toBe("new-pw");
    expect(view.login.username).toBe("me");
    expect(view.login.uris).toHaveLength(1);
    expect(view.fields).toHaveLength(1);
  });

  it("sets username, notes and a trimmed totp seed", () => {
    const view = login();
    applyField(view, "username", "you");
    applyField(view, "notes", "remember");
    applyField(view, "totp", "  JBSWY3DPEHPK3PXP\n");
    expect(view.login.username).toBe("you");
    expect(view.notes).toBe("remember");
    expect(view.login.totp).toBe("JBSWY3DPEHPK3PXP");
  });

  it("updates an existing custom field and keeps its type", () => {
    const view = login();
    view.fields.push(
      Object.assign(Object.create(Object.getPrototypeOf(view.fields[0])), {
        name: "token",
        value: "old",
        type: FieldType.Text,
      }),
    );
    applyField(view, "custom:token", "new");
    const token = view.fields.find((field) => field.name === "token");
    expect(token).toMatchObject({ value: "new", type: FieldType.Text });
    expect(view.fields).toHaveLength(2);
  });

  it("adds a missing custom field as hidden", () => {
    const view = login();
    applyField(view, "custom:api key", "secret");
    expect(view.fields.find((field) => field.name === "api key")).toMatchObject({
      value: "secret",
      type: FieldType.Hidden,
    });
  });

  it("refuses ambiguous and linked custom fields", () => {
    const view = login();
    const make = (type: number) =>
      Object.assign(Object.create(Object.getPrototypeOf(view.fields[0])), {
        name: "dup",
        value: "v",
        type,
      });
    view.fields.push(make(FieldType.Text), make(FieldType.Text));
    expect(() => applyField(view, "custom:dup", "x")).toThrow("not unique");

    const linked = login();
    linked.fields.push(make(FieldType.Linked));
    expect(() => applyField(linked, "custom:dup", "x")).toThrow("Linked");
  });

  it("changes only notes on an item that is not a login", () => {
    const view = login();
    view.type = CipherType.SecureNote;
    view.login = undefined as never;
    expect(() => applyField(view, "password", "x")).toThrow("only be changed on a login");
    applyField(view, "notes", "text");
    expect(view.notes).toBe("text");
  });

  it("refuses to change a read-only item", () => {
    const view = login();
    view.edit = false;
    expect(() => applyField(view, "password", "x")).toThrow(
      expect.objectContaining({ code: "PERMISSION_DENIED" }),
    );
    expect(view.login.password).toBe("old-pw");
  });
});

describe("isTotpSeed", () => {
  it("accepts the documented seed formats", () => {
    for (const seed of [
      "JBSWY3DPEHPK3PXP",
      "jbswy3dpehpk3pxp",
      "JBSW Y3DP EHPK 3PXP",
      "jbswy3dp-ehpk3pxp\n",
      "MFRGGZDFMZTWQ2LK====",
      "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
      "steam://JBSWY3DPEHPK3PXP",
    ]) {
      expect(isTotpSeed(seed)).toBe(true);
    }
  });

  it("rejects text that is not a seed", () => {
    for (const seed of [
      "",
      "   ",
      "%%% not a seed %%%",
      "short",
      "JBSWY3DP0HPK3PXP",
      "not base32 because of 1 and 8",
      "otpauth://totp/GitHub:me",
      "otpauth://hotp/GitHub:me?secret=JBSWY3DPEHPK3PXP",
      "https://example.test/JBSWY3DPEHPK3PXP",
    ]) {
      expect(isTotpSeed(seed)).toBe(false);
    }
  });

  it("is checked before a totp change is accepted, without echoing the value", () => {
    expect(() => parseFieldChange({ ref: "ref:x", field: "totp", value: "%%% nope %%%" })).toThrow(
      expect.objectContaining({ code: "INVALID_TOTP", exitCode: 2 }),
    );
    try {
      parseFieldChange({ ref: "ref:x", field: "totp", value: "%%% nope %%%" });
    } catch (error) {
      expect((error as Error).message).not.toContain("nope");
    }
    expect(parseFieldChange({ ref: "ref:x", field: "totp", value: "JBSWY3DPEHPK3PXP" }).field).toBe(
      "totp",
    );
  });

  it("does not apply to other fields", () => {
    expect(parseFieldChange({ ref: "ref:x", field: "notes", value: "%%% nope %%%" }).field).toBe(
      "notes",
    );
  });
});

describe("writeFailure", () => {
  it("recognises a stale copy as a conflict", () => {
    for (const text of [
      "The client copy of this cipher is out of date. Resolve the conflict and try again.",
      "409 Conflict",
    ]) {
      expect(writeFailure(new Error(text))).toMatchObject({ code: "WRITE_CONFLICT", exitCode: 8 });
    }
  });

  it("recognises the conflict the way the upstream API client actually raises it", () => {
    // The API client throws an ErrorResponse, which is not an Error: it only has a message
    // and a status. The text is the one the server was seen to send for an old copy.
    const refusal = new ErrorResponse(
      {
        Message:
          "The client copy of this cipher is out of date. Resolve the conflict and try again.",
      },
      400,
    );
    expect(refusal).not.toBeInstanceOf(Error);
    expect(writeFailure(refusal)).toMatchObject({ code: "WRITE_CONFLICT", exitCode: 8 });
    expect(writeFailure({ statusCode: 409 })).toMatchObject({ code: "WRITE_CONFLICT" });
  });

  it("does not take a plain failure for a conflict, whatever shape it has", () => {
    for (const error of [
      new ErrorResponse({ Message: "Internal server error" }, 500),
      { message: 5 },
      { statusCode: 400 },
      null,
      undefined,
    ]) {
      expect(writeFailure(error)).toMatchObject({ code: "WRITE_FAILED" });
    }
  });

  it("reports anything else as a rejected write, without echoing the cause", () => {
    const failure = writeFailure(new Error("500 secret-token in the server response"));
    expect(failure).toMatchObject({ code: "WRITE_FAILED" });
    expect(failure.message).not.toContain("secret-token");
    expect(writeFailure("a string")).toMatchObject({ code: "WRITE_FAILED" });
  });

  it("passes AkbError through unchanged", () => {
    const original = new AkbError("NOT_FOUND", "Account not found.", 5);
    expect(writeFailure(original)).toBe(original);
  });
});
