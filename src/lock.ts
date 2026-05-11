import { mkdir, readFile, rm, stat, writeFile } from "fs/promises";
import { hostname } from "os";
import { join } from "path";

import { logger } from "./logger.js";

const DEFAULT_STALE_MS = 5 * 60 * 1000;
const DEFAULT_WAIT_MS = 90 * 1000;
const RETRY_INTERVAL_MS = 200;

export type LockOptions = {
  waitMs?: number;
  staleMs?: number;
};

type LockInfo = {
  pid: number;
  host: string;
  acquiredAt: string;
};

export async function withLock<T>(
  lockPath: string,
  callback: () => Promise<T>,
  options: LockOptions = {},
): Promise<T> {
  const waitMs = options.waitMs ?? DEFAULT_WAIT_MS;
  const staleMs = options.staleMs ?? DEFAULT_STALE_MS;

  await acquire(lockPath, waitMs, staleMs);
  try {
    return await callback();
  } finally {
    await release(lockPath);
  }
}

async function acquire(
  lockPath: string,
  waitMs: number,
  staleMs: number,
): Promise<void> {
  const deadline = Date.now() + waitMs;
  logger.debug(`Acquiring lock`, { lockPath });

  while (true) {
    try {
      //
      // mkdir is atomic on POSIX: exactly one caller succeeds, the rest
      // see EEXIST. That's the entire mutual-exclusion guarantee.
      //
      await mkdir(lockPath);
      const info: LockInfo = {
        pid: process.pid,
        host: hostname(),
        acquiredAt: new Date().toISOString(),
      };
      await writeFile(join(lockPath, "info"), JSON.stringify(info));
      logger.debug(`Lock acquired`, { lockPath });
      return;
    } catch (e: unknown) {
      if (!isEexistError(e)) throw e;

      if (await tryStealStale(lockPath, staleMs)) continue;

      if (Date.now() >= deadline) {
        throw new Error(`Timed out after ${waitMs}ms waiting for lock`);
      }

      await new Promise((r) => setTimeout(r, RETRY_INTERVAL_MS));
    }
  }
}

async function tryStealStale(
  lockPath: string,
  staleMs: number,
): Promise<boolean> {
  let info: LockInfo | undefined;
  try {
    info = JSON.parse(await readFile(join(lockPath, "info"), "utf8"));
  } catch {
    //
    // The info file may not exist yet (the holder is between mkdir and
    // writeFile), or the lock may have just been released. Fall through to
    // the mtime check.
    //
  }

  if (info && info.host === hostname() && !isProcessAlive(info.pid)) {
    logger.warn(`Stealing lock from dead pid`, {
      lockPath,
      pid: info.pid,
    });
    await rm(lockPath, { recursive: true, force: true });
    return true;
  }

  try {
    const s = await stat(lockPath);
    if (Date.now() - s.mtimeMs > staleMs) {
      logger.warn(`Stealing stale lock`, {
        lockPath,
        ageMs: Date.now() - s.mtimeMs,
      });
      await rm(lockPath, { recursive: true, force: true });
      return true;
    }
  } catch {
    //
    // Lock dir disappeared between our failed mkdir and this stat — the
    // holder released. Caller should retry mkdir immediately.
    //
    return true;
  }

  return false;
}

async function release(lockPath: string): Promise<void> {
  try {
    await rm(lockPath, { recursive: true, force: true });
    logger.debug(`Lock released`, { lockPath });
  } catch (e) {
    logger.warn(`Failed to release lock`, { lockPath, error: e });
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e: unknown) {
    if (e instanceof Error && "code" in e && e.code === "ESRCH") return false;
    //
    // EPERM means the process exists but we lack permission to signal it.
    // Treat as alive — better to wait than to steal a live process's lock.
    //
    return true;
  }
}

function isEexistError(e: unknown): boolean {
  return (
    e instanceof Error &&
    "code" in e &&
    (e as { code: string }).code === "EEXIST"
  );
}
