import { tmpdir } from "os";
import { join } from "path";

export const LOCK_FILE_NAME = join(tmpdir(), "opaws.lock");

export function sanitizeFilename(filename: string) {
  return filename.replace(/[/\\?%*:|"<>]/g, "-");
}

export function isFileNotFoundError(
  e: unknown,
): e is Error & { code: "ENOENT" } {
  if (!(e instanceof Error)) return false;
  if (!("code" in e)) return false;
  return e.code === "ENOENT";
}
