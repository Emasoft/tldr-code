export interface Token {
  name: string;
}

export function build(name: string): string {
  return `type:${name}`;
}
