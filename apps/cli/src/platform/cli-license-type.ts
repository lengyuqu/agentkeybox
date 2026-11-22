/**
 * The license the running CLI build was produced under. The values match the `bw-{license}-*`
 * prefix of the CLI release assets.
 */
export const CliLicenseType = Object.freeze({
  /** Built from `apps/cli` (GPL). */
  Oss: "oss",
  /** Commercial CLI distribution (`bw-bit-*` release assets); not built from this repository. */
  Bit: "bit",
} as const);
export type CliLicenseType = (typeof CliLicenseType)[keyof typeof CliLicenseType];
