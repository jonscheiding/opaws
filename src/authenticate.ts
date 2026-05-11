import { exec } from "child_process";
import { readFile, rename, writeFile } from "fs/promises";
import assert from "node:assert";
import { tmpdir } from "os";
import { join } from "path";

import op, { Item } from "@1password/op-js";
import { Credentials, STS, STSServiceException } from "@aws-sdk/client-sts";
import { Command } from "@commander-js/extra-typings";
import { keyBy } from "lodash-es";
import timestring from "timestring";
import { z } from "zod";

import { withLock } from "./lock.js";
import { configureDebugLogging, LOG_FILENAME, logger } from "./logger.js";
import { notify } from "./notifier.js";
import { isFileNotFoundError, sanitizeFilename } from "./util.js";

type AwsKeys = {
  accessKeyId: string;
  secretAccessKey: string;
} & (
  | { totp: undefined; mfaSerial: undefined }
  | { totp: string; mfaSerial: string }
);

type BaseCreds = {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
};

const opSchema = z
  .object({
    "access key id": z.object({
      type: z.literal("STRING"),
      value: z.string(),
    }),
    "secret access key": z.object({
      type: z.union([z.literal("CONCEALED"), z.literal("STRING")]),
      value: z.string(),
    }),
  })
  .and(
    z.union([
      z.object({
        "mfa serial": z.object({
          type: z.literal("STRING"),
          value: z.string(),
        }),
        "one-time password": z.object({
          type: z.literal("OTP"),
          totp: z.string(),
        }),
      }),
      z.object({
        "mfa serial": z.undefined(),
        "one-time password": z.undefined(),
      }),
    ]),
  );

const cachedCredentialsSchema = z.object({
  AccessKeyId: z.string(),
  SecretAccessKey: z.string(),
  SessionToken: z.string(),
  Expiration: z
    .string()
    .datetime()
    .transform((s) => new Date(s)),
});

type CachedCredentials = z.infer<typeof cachedCredentialsSchema>;

export const command = new Command("authenticate")
  .option("-r, --role-arn <role ARN>", "Specify a role to assume.")
  .option(
    "-s, --role-session-name <role session name>",
    "Specify a session name for the assumed role session.",
  )
  .requiredOption(
    "-i, --op-item <op item>",
    `Name or ID of the 1Password item containing the AWS access keys.`,
  )
  .option(
    "-v, --op-vault <op vault name>",
    "Name or ID of the 1Password vault containing the item.",
  )
  .option(
    "-a, --op-account <op account name>",
    "Name or ID of the 1Password account containing the item.",
  )
  .option(
    "-d, --duration <duration>",
    "Duration of the session. Expressed as a time string, see https://www.npmjs.com/package/timestring.",
    (value) => timestring(value),
  )
  .option("--debug", "Log debug messages to the console.")
  .option("--no-cache", "Do not use cached credentials if they exist.")
  .description("Generates credentials as an AWS CLI credential_process.")
  .action(authenticate);

type AuthenticateOptions = ReturnType<typeof command.opts>;

function isInvalidMfaError(e: unknown): e is STSServiceException & {
  Code: "AccessDenied";
  message: "MultiFactorAuthentication failed with invalid MFA one time pass code. ";
} {
  if (!(e instanceof STSServiceException)) return false;
  if (!("Code" in e)) return false;
  if (!("message" in e)) return false;
  return (
    e.Code === "AccessDenied" &&
    e.message ===
      "MultiFactorAuthentication failed with invalid MFA one time pass code. "
  );
}

function getTotpSecondsRemaining() {
  //
  // TOTPs cycle every 30 seconds starting at the unix epoch
  //
  const secondsSinceEpoch = Math.floor(Date.now() / 1000);
  return 30 - (secondsSinceEpoch % 30);
}

function tmpFile(prefix: string, parts: (string | undefined)[], ext: string) {
  const key = [prefix, ...parts.map((p) => p ?? "default")].join("-");
  return join(tmpdir(), sanitizeFilename(`${key}.${ext}`));
}

function getSessionCacheFilename(options: AuthenticateOptions) {
  return tmpFile(
    "opaws-cache-session",
    [options.opAccount, options.opVault, options.opItem],
    "json",
  );
}

function getRoleCacheFilename(options: AuthenticateOptions) {
  assert.ok(options.roleArn);
  return tmpFile(
    "opaws-cache-role",
    [
      options.opAccount,
      options.opVault,
      options.opItem,
      options.roleArn,
      options.roleSessionName,
    ],
    "json",
  );
}

function getSessionLockDirectory(options: AuthenticateOptions) {
  const key = [
    "opaws-lock-session",
    options.opAccount ?? "default",
    options.opVault ?? "default",
    options.opItem,
  ].join("-");
  return join(tmpdir(), sanitizeFilename(key));
}

async function readCachedCredentials(
  filename: string,
): Promise<CachedCredentials | undefined> {
  let data: string;
  try {
    data = (await readFile(filename)).toString();
  } catch (e) {
    if (!isFileNotFoundError(e)) throw e;
    logger.debug(`No cached credentials found.`, { filename });
    return undefined;
  }

  try {
    const creds = cachedCredentialsSchema.parse(JSON.parse(data));
    if (creds.Expiration.getTime() < Date.now()) {
      logger.info(`Cached credentials expired as of ${creds.Expiration}.`, {
        filename,
      });
      return undefined;
    }
    logger.debug(`Found cached credentials`, { filename });
    return creds;
  } catch (e) {
    logger.warn(`Invalid cached credentials.`, e);
    return undefined;
  }
}

async function writeCachedCredentials(filename: string, creds: Credentials) {
  //
  // Write to a temp file then rename, so a concurrent reader never sees
  // a half-written JSON document.
  //
  const tmp = `${filename}.tmp.${process.pid}`;
  await writeFile(tmp, JSON.stringify(creds, null, 2));
  await rename(tmp, filename);
}

function get1pAwsKeys(options: AuthenticateOptions): AwsKeys {
  const { opAccount, opVault, opItem } = options;

  logger.debug(`Looking for item in 1password`, {
    opAccount,
    opVault,
    opItem,
  });

  const item = op.item.get(opItem, {
    account: opAccount,
    vault: opVault,
  }) as Item;

  logger.debug(`Found 1password item`, {
    id: item.id,
    title: item.title,
    vault: item.vault,
  });

  const fields = opSchema.safeParse(keyBy(item.fields, "label"));

  if (!fields.success) {
    logger.warn(fields.error);
    logger.error(command.helpInformation());
    throw new Error(
      `1Password item ${item.id} is missing some fields, or they are the wrong type`,
    );
  }

  return {
    accessKeyId: fields.data["access key id"].value,
    secretAccessKey: fields.data["secret access key"].value,
    mfaSerial: fields.data["mfa serial"]?.value,
    totp: fields.data["one-time password"]?.totp,
  } as AwsKeys;
}

async function fetchSessionToken(
  keys: AwsKeys,
  durationSeconds: number | undefined,
): Promise<Credentials> {
  const sts = new STS({
    credentials: {
      accessKeyId: keys.accessKeyId,
      secretAccessKey: keys.secretAccessKey,
    },
  });

  const response = await sts.getSessionToken({
    SerialNumber: keys.mfaSerial,
    TokenCode: keys.totp,
    DurationSeconds: durationSeconds,
  });

  if (response.Credentials == null) {
    throw new Error("STS GetSessionToken returned no credentials.");
  }
  return response.Credentials;
}

async function fetchAssumedRole(
  baseCreds: BaseCreds,
  options: AuthenticateOptions,
): Promise<Credentials> {
  assert.ok(options.roleArn);

  const sts = new STS({ credentials: baseCreds });

  const response = await sts.assumeRole({
    RoleArn: options.roleArn,
    RoleSessionName:
      options.roleSessionName ?? `temporary-session-${Date.now().toString()}`,
    DurationSeconds: options.duration
      ? Math.min(options.duration, 60 * 60 * 1000)
      : undefined,
  });

  if (response.Credentials == null) {
    throw new Error("STS AssumeRole returned no credentials.");
  }
  return response.Credentials;
}

async function getOrFetchSessionCredentials(
  options: AuthenticateOptions,
): Promise<CachedCredentials | Credentials> {
  const cacheFile = getSessionCacheFilename(options);

  if (options.cache) {
    const cached = await readCachedCredentials(cacheFile);
    if (cached) return cached;
  } else {
    logger.debug("Skipping session cache");
  }

  return withLock(getSessionLockDirectory(options), async () => {
    //
    // Re-check after acquiring the lock: a concurrent process may have
    // populated the cache while we were waiting.
    //
    if (options.cache) {
      const cached = await readCachedCredentials(cacheFile);
      if (cached) return cached;
    }

    //
    // When chained into AssumeRole, the role session is hard-capped at 1 hour
    // regardless of how long the underlying session-creds live. So we only
    // honour --duration here in the standalone case; otherwise let the
    // session-token call default (12 hours) so MFA isn't re-prompted often.
    //
    const sessionDuration =
      options.roleArn != null ? undefined : options.duration;

    let keys = get1pAwsKeys(options);
    let creds: Credentials | undefined;

    for (let i = 0; i < 2 && creds == null; i++) {
      try {
        creds = await fetchSessionToken(keys, sessionDuration);
      } catch (e) {
        if (!isInvalidMfaError(e) || i > 0) throw e;

        const pauseSeconds = getTotpSecondsRemaining() + 3;
        logger.warn(
          `Invalid MFA code on first attempt. Pausing for ${pauseSeconds} seconds to try again in case of reuse.`,
        );
        await new Promise((resolve) =>
          setTimeout(resolve, pauseSeconds * 1000),
        );
        keys = get1pAwsKeys(options);
      }
    }

    assert.ok(creds != null);
    await writeCachedCredentials(cacheFile, creds);
    return creds;
  });
}

async function getOrFetchRoleCredentials(
  options: AuthenticateOptions,
): Promise<CachedCredentials | Credentials> {
  assert.ok(options.roleArn);

  const cacheFile = getRoleCacheFilename(options);

  if (options.cache) {
    const cached = await readCachedCredentials(cacheFile);
    if (cached) return cached;
  } else {
    logger.debug("Skipping role cache");
  }

  //
  // Always go through the session-creds path. This serialises the 1P read
  // behind the session lock, so concurrent invocations for different roles
  // under the same IAM user trigger at most one Touch ID prompt rather than
  // one per profile.
  //
  // Tradeoff: AssumeRole chained from a session token is hard-capped at 1
  // hour by AWS. The credential_process gets re-invoked on expiry, so this
  // is transparent in normal use.
  //
  const session = await getOrFetchSessionCredentials(options);
  const baseCreds: BaseCreds = {
    accessKeyId: session.AccessKeyId!,
    secretAccessKey: session.SecretAccessKey!,
    sessionToken: session.SessionToken!,
  };

  const creds = await fetchAssumedRole(baseCreds, options);
  await writeCachedCredentials(cacheFile, creds);
  return creds;
}

async function generateCredentials(options: AuthenticateOptions) {
  logger.info(`Generating credentials`, options);

  const creds =
    options.roleArn != null
      ? await getOrFetchRoleCredentials(options)
      : await getOrFetchSessionCredentials(options);

  console.log(
    JSON.stringify(
      {
        ...creds,
        Version: 1,
      },
      null,
      2,
    ),
  );
}

async function authenticate(options: AuthenticateOptions) {
  if (options.debug) {
    configureDebugLogging();
  }

  try {
    await generateCredentials(options);
  } catch (e) {
    console.error(`Failed to generate credentials.`);
    console.error(`Debug log saved to ${LOG_FILENAME}.`);

    logger.error(e);

    if (!process.stdout.isTTY) {
      const result = await notify({
        title: "OPAWS",
        message:
          (e instanceof Error ? e.message : undefined) ??
          "Error generating credentials",
        actions: ["View Log"],
      });

      if (result?.kind === "action" && result.action === "View Log") {
        exec(`open ${LOG_FILENAME}`).unref();
      }
    }
    process.exit(1);
  }
}
