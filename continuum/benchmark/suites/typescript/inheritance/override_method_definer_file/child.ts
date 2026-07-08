import { Base } from "./base";

export class Child extends Base {
  helper(): string {
    return "child";
  }

  run(): string {
    return this.helper();
  }
}
