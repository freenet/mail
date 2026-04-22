import { readFileSync } from "node:fs";
import { join } from "node:path";

// Single source of truth for the consumer-facing product name, shared
// verbatim with the Rust UI via `ui/branding/app-name.txt`. The Rust
// side reads the same file at compile time through `include_str!`
// (see `APP_NAME` in ui/src/lib.rs).
export const APP_NAME = readFileSync(
  join(__dirname, "..", "branding", "app-name.txt"),
  "utf8",
).trim();
