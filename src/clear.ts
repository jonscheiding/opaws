import { rm, readdir } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

import { Command } from "@commander-js/extra-typings";

import { isFileNotFoundError, LOCK_FILE_NAME } from "./util.js";

export const command = new Command("clear")
  .option("-l, --logs", "Clear only OPAWS log files")
  .option("-c, --cache", "Clear only OPAWS cached credentials")
  .option("-f, --lock-file", "Clear only OPAWS lock file")
  .action(async (options) => {
    const entries = await readdir(tmpdir());

    const all = !options.cache && !options.logs && !options.lockFile;

    if (options.logs || all) {
      const logFiles = entries.filter((e) => e.startsWith("opaws-log-"));
      await Promise.all(logFiles.map((file) => rm(join(tmpdir(), file))));
      console.log(`Removed ${logFiles.length} log files.`);
    }

    if (options.cache || all) {
      const cacheFiles = entries.filter((e) => e.startsWith("opaws-cache-"));
      await Promise.all(cacheFiles.map((file) => rm(join(tmpdir(), file))));
      console.log(`Removed ${cacheFiles.length} cache files.`);
    }

    if (options.lockFile || all) {
      try {
        await rm(LOCK_FILE_NAME);
        console.log(`Lock file removed.`);
      } catch (e) {
        if (isFileNotFoundError(e)) {
          console.log(`Lock file does not exist.`);
        } else {
          throw e;
        }
      }
    }
  });
