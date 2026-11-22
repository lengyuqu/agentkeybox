import { credential, failure, metadata, selectItem } from "./protocol";

describe("AgentKeybox credential boundary", () => {
  const item = {
    id: "one",
    name: "Test",
    login: { username: "user", password: "secret-password" },
    notes: "secret-note",
    fields: [
      { name: "agentkeybox.ref", value: "test/work" },
      { name: "token", value: "secret-token" },
    ],
  };
  it("never includes secret values in discovery metadata", () => {
    const output = JSON.stringify(metadata(item));
    expect(output).not.toContain("secret-");
    expect(metadata(item).credential_fields).toContain("custom:token");
  });
  it("reads only an explicitly selected field", () => {
    expect(credential(item, "custom:token")).toBe("secret-token");
    expect(() => credential(item, "token")).toThrow("custom:");
    expect(() => credential({ ...item, viewPassword: false }, "password")).toThrow("restricted");
  });
  it("requires stable references and rejects ambiguity and deleted entries", () => {
    expect(selectItem([item], "ref:test/work")).toBe(item);
    expect(() => selectItem([item], "Test")).toThrow("id:");
    expect(() => selectItem([item, { ...item, id: "two" }], "ref:test/work")).toThrow("not unique");
    expect(() => selectItem([{ ...item, isDeleted: true }], "id:one")).toThrow("not found");
  });
  it("does not echo unknown upstream error payloads", () => {
    expect(JSON.stringify(failure(new Error("secret-token")))).not.toContain("secret-token");
  });
  it("handles empty values, duplicate names and linked fields explicitly", () => {
    expect(credential({ ...item, login: { password: "" } }, "password")).toBe("");
    expect(() => credential(item, "custom:missing")).toThrow("not found");
    expect(() =>
      credential(
        {
          ...item,
          fields: [
            { name: "x", value: "a" },
            { name: "x", value: "b" },
          ],
        },
        "custom:x",
      ),
    ).toThrow("not unique");
    expect(() =>
      credential({ ...item, fields: [{ name: "x", value: "100", type: 3 }] }, "custom:x"),
    ).toThrow("Linked fields");
  });
});
