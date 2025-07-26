export class Logger {
  private verbose = import.meta.env.MODE === 'development';

  setVerbose(value: boolean) {
    this.verbose = value;
  }

  debug(...args: unknown[]) {
    if (this.verbose) {
      console.debug(...args);
    }
  }

  info(...args: unknown[]) {
    console.info(...args);
  }

  warn(...args: unknown[]) {
    console.warn(...args);
  }

  error(...args: unknown[]) {
    console.error(...args);
  }
}

export const logger = new Logger();
