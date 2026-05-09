import { rm, readdir } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

import { Command } from "@commander-js/extra-typings";

export const command = new Command("clear")
  .option("-l, --logs", "Clear only OPAWS log files")
  .option("-c, --cache", "Clear only OPAWS cached credentials")
  .option("-f, --lock-file", "Clear only OPAWS lock files")
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
      const lockFiles = entries.filter(
        (e) => e === "opaws.lock" || e.startsWith("opaws-lock-"),
      );
      await Promise.all(lockFiles.map((file) => rm(join(tmpdir(), file))));
      console.log(`Removed ${lockFiles.length} lock files.`);
    }
  });
