import { readFileSync } from "node:fs";
import { join } from "node:path";

// Single source of truth for the consumer-facing branding, shared
// verbatim with the Rust UI via `ui/branding/app.json`. The Rust
// side reads the same file at startup through `include_str!` +
// `serde_json` (see `branding::app_name` in ui/src/lib.rs).
interface Branding {
  name: string;
}

const branding: Branding = JSON.parse(
  readFileSync(join(__dirname, "..", "branding", "app.json"), "utf8"),
);

export const APP_NAME = branding.name;
