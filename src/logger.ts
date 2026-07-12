function write(level: string, message: string): void {
  process.stderr.write(`${new Date().toISOString()} [${level}] ${message}\n`);
}

export const logger = {
  info(message: string): void {
    write("info", message);
  },
  warn(message: string): void {
    write("warn", message);
  },
  error(message: string): void {
    write("error", message);
  },
};
