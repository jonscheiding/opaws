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
