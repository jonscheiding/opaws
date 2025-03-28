import { tmpdir } from "os";
import { join } from "path";

import { MESSAGE } from "triple-beam";
import winston from "winston";

export const LOG_FILENAME = join(
  tmpdir(),
  `opaws-log-${Date.now()}-${process.pid}.log`,
);

const consoleTransport = new winston.transports.Console({
  level: "error",
});

export const logger = winston.createLogger({
  level: "debug",
  format: winston.format.combine(winston.format.simple(), {
    transform: (info) => {
      info[MESSAGE] =
        `${new Date().toISOString()} ${process.pid} ${info[MESSAGE]}`;
      return info;
    },
  }),
  transports: [
    consoleTransport,
    new winston.transports.File({ filename: LOG_FILENAME }),
  ],
});

export function configureDebugLogging() {
  consoleTransport.level = "debug";
}
