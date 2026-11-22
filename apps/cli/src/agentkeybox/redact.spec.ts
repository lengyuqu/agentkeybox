import { Redactor } from "./redact";

function filter(secrets: Record<string, string>, chunks: (string | Buffer)[]): string {
  const redactor = new Redactor(secrets);
  const parts = chunks.map((chunk) => redactor.write(Buffer.from(chunk)));
  parts.push(redactor.end());
  return Buffer.concat(parts).toString("latin1");
}

describe("Redactor", () => {
  const secrets = { TOKEN: "s3cr3t-Value/+=" };

  it("replaces a value with its variable name", () => {
    expect(filter(secrets, ["token is s3cr3t-Value/+= ok"])).toBe("token is [REDACTED:TOKEN] ok");
  });

  it("passes unrelated output through untouched", () => {
    expect(filter(secrets, ["nothing here\n", "still nothing\n"])).toBe(
      "nothing here\nstill nothing\n",
    );
  });

  it("catches a value split at every possible chunk boundary", () => {
    const text = "before s3cr3t-Value/+= after";
    for (let split = 1; split < text.length; split++) {
      expect(filter(secrets, [text.slice(0, split), text.slice(split)])).toBe(
        "before [REDACTED:TOKEN] after",
      );
    }
  });

  it("catches a value delivered one byte at a time", () => {
    const text = "x s3cr3t-Value/+= y";
    expect(filter(secrets, [...text])).toBe("x [REDACTED:TOKEN] y");
  });

  it("redacts the common encodings of a value", () => {
    const value = 'p@ss "word"/1';
    const raw = Buffer.from(value);
    const output = filter({ PW: value }, [
      `plain=${value}\n`,
      `json=${JSON.stringify(value).slice(1, -1)}\n`,
      `url=${encodeURIComponent(value)}\n`,
      `b64=${raw.toString("base64")}\n`,
      `b64url=${raw.toString("base64url")}\n`,
      `hex=${raw.toString("hex")}\n`,
    ]);
    expect(output).not.toContain(value);
    expect(output.match(/\[REDACTED:PW\]/g)).toHaveLength(6);
  });

  it("prefers the longer value when one secret contains another", () => {
    expect(filter({ SHORT: "abcd", LONG: "abcdefgh" }, ["x abcdefgh y"])).toBe(
      "x [REDACTED:LONG] y",
    );
  });

  it("never rescans its own label", () => {
    // "ACTED" occurs inside the replacement text. It must not be replaced a second time.
    const output = filter({ A: "ACTED", B: "other-secret" }, ["ACTED then other-secret\n"]);
    expect(output).toBe("[REDACTED:A] then [REDACTED:B]\n");
  });

  it("leaves non-UTF-8 bytes intact", () => {
    const input = Buffer.from([0xa1, 0xb2, 0x00, 0xff, 0x41]);
    const redactor = new Redactor(secrets);
    const output = Buffer.concat([redactor.write(input), redactor.end()]);
    expect(output.equals(input)).toBe(true);
  });

  it("redacts a non-ASCII secret written as UTF-8", () => {
    expect(filter({ PW: "pässwörd-1" }, [Buffer.from("got pässwörd-1 here")])).toBe(
      "got [REDACTED:PW] here",
    );
  });

  it("does not redact values too short to be meaningful", () => {
    expect(filter({ PIN: "12" }, ["port 1234 and 12"])).toBe("port 1234 and 12");
  });

  it("releases held-back text when the stream ends", () => {
    const redactor = new Redactor(secrets);
    const first = redactor.write(Buffer.from("tail s3cr3"));
    const rest = redactor.end();
    expect(Buffer.concat([first, rest]).toString()).toBe("tail s3cr3");
  });

  it("is a plain pass-through with no secrets", () => {
    expect(filter({}, ["abc", "def"])).toBe("abcdef");
  });
});
