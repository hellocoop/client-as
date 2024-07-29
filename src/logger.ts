const LOG_LEVEL = process.env.LOG_LEVEL || "info";

interface LogAttributes {
  [key: string]: string | number | boolean | unknown | undefined | Error;
}

export function log(msg: string, level: "debug" | "info" | "warn" | "error", attributes?: LogAttributes) {
  if (LOG_LEVEL === "info" && level === "debug") {
    return;
  }

  if (LOG_LEVEL === "warn" && ["debug", "info"].includes(level)) {
    return;
  }

  if (LOG_LEVEL === "error" && level !== "error") {
    return;
  }

  const message = { msg, level, ...attributes };
  //eslint-disable-next-line no-console
  console.log(JSON.stringify(message));
}

export function debug(msg: string, attributes?: LogAttributes) {
  log(msg, "debug", attributes);
}

export function info(msg: string, attributes?: LogAttributes) {
  log(msg, "info", attributes);
}

export function warn(msg: string, attributes?: LogAttributes) {
  log(msg, "warn", attributes);
}

export function error(msg: string, attributes?: LogAttributes) {
  log(msg, "error", attributes);
}

export function formatError(error: Error | unknown): { error: string } {
  if (!(error instanceof Error)) {
    return { error: JSON.stringify({message: 'unable to format error'}) };
  }
  const { message, stack, name } = error;
  return { error: JSON.stringify({ message, stack: stack?.replaceAll('\n', ';'), name }) };
}