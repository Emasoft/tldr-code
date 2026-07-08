export class Service {
  helper(): string {
    return "ok";
  }

  run(): string {
    return this.helper();
  }
}
