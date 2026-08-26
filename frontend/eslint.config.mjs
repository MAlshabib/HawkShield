import { dirname } from "path";
import { fileURLToPath } from "url";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({
  baseDirectory: __dirname,
});

const eslintConfig = [
  {
    ignores: [".next/**", "out/**", "node_modules/**", "next-env.d.ts"],
  },

  ...compat.extends("next/core-web-vitals", "next/typescript"),

  // NOTE: these overrides must come AFTER the `extends` above — in flat config
  // the last matching block wins. They were previously listed first, which is
  // why `next/typescript` kept re-enabling them and broke `next build`.
  //
  // The API responses are loosely typed on purpose (the backend returns raw
  // `packets` rows with several legacy field aliases), so `any` is downgraded to
  // a warning rather than a build-breaking error.
  {
    rules: {
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": "warn",
    },
  },
];

export default eslintConfig;
