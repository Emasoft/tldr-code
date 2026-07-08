import type { Token } from "./types";
import { build } from "./builder";

export function run(token: Token): string {
  return build(token.name);
}
