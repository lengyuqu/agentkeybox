const path = require("path");
const { buildConfig } = require("./webpack.base");

const config = buildConfig({
  configName: "AgentKeybox GPL",
  entry: "./src/agentkeybox/main.ts",
  tsConfig: "./tsconfig.json",
  outputPath: path.resolve(__dirname, "build-akb"),
  mode: "production",
  env: "production",
});
config.entry = { akb: "./src/agentkeybox/main.ts" };
module.exports = config;
