const mode = (import.meta as any)?.env?.MODE ?? process.env.NODE_ENV;

export class Logger {
  /**
   * Verbose logging is enabled by default when running in development mode.
   * Call `setVerbose(true | false)` to override this behavior at runtime.
   */
  private verbose = mode === 'development';

  /** Override the default verbosity. */
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
