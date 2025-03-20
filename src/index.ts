import { exec } from "child_process";
import { closeSync, openSync } from "fs";
import { readFile, writeFile } from "fs/promises";
import assert from "node:assert";
import { tmpdir } from "os";
import { join } from "path";

import op, { Item } from "@1password/op-js";
import { Credentials, STS, STSServiceException } from "@aws-sdk/client-sts";
import { Command } from "@commander-js/extra-typings";
import { lock, LockCallback } from "cross-process-lock";
import { keyBy } from "lodash-es";
import notifier from "node-notifier";
import timestring from "timestring";
import { MESSAGE } from "triple-beam";
import winston from "winston";
import { z } from "zod";

type AwsKeys = {
  accessKeyId: string;
  secretAccessKey: string;
} & (
  | { totp: undefined; mfaSerial: undefined }
  | { totp: string; mfaSerial: string }
);

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

const program = new Command()
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
  .description(
    "Generates temporary AWS credentials in the form expected by the aws profile credential_process, " +
      "using permanent credentials stored in 1Password.\n" +
      `The 1Password item must have certain fields.
Required:
  access key id - Text
  secret access key - Text or Password
Optional (must both be present, or neither):
  mfa serial - Text
  one-time password - One-Time Password`,
  );

const options = program.parse(process.argv).opts();

const logFilename = join(
  tmpdir(),
  `opaws-log-${Date.now()}-${process.pid}.log`,
);

const logger = winston.createLogger({
  level: "debug",
  format: winston.format.combine(winston.format.simple(), {
    transform: (info) => {
      info[MESSAGE] =
        `${new Date().toISOString()} ${process.pid} ${info[MESSAGE]}`;
      return info;
    },
  }),
  transports: [
    new winston.transports.Console({
      level: options.debug ? "debug" : "error",
    }),
    new winston.transports.File({ filename: logFilename }),
  ],
});

function sanitizeFilename(filename: string) {
  return filename.replace(/[/\\?%*:|"<>]/g, "-");
}

function isFileNotFoundError(e: unknown): e is Error & { code: "ENOENT" } {
  if (!(e instanceof Error)) return false;
  if (!("code" in e)) return false;
  return e.code === "ENOENT";
}

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

function getCacheFilename() {
  const { opAccount, opVault, opItem, roleArn, roleSessionName } = options;

  const cacheKey = [
    "opaws-cache",
    opAccount ?? "default",
    opVault ?? "default",
    opItem,
    roleArn ?? "default",
    roleSessionName ?? "default",
  ].join("-");

  return join(tmpdir(), sanitizeFilename(`${cacheKey}.json`));
}

async function withLockInternal<T>(callback: LockCallback<T>) {
  const lockFileName = join(tmpdir(), "opaws.lock");

  //
  // ensure lock file exists - cross-process-lock doesn't create it for you
  //
  closeSync(openSync(lockFileName, "w"));

  //
  // cross-process-lock seems to have a race condition where two processes can get the lock
  // if they ask at exactly the same instant
  // we can't "fix" this but we can introduce some jitter to make it less likely for applications
  // that are authenticating a bunch of profiles at the same time
  //
  const jitter = Math.random() * 500;
  logger.debug(`Jittering for ${jitter}ms`);
  await new Promise((resolve) => setTimeout(resolve, jitter));

  const release = await lock(lockFileName, {
    lockTimeout: 30000,
  });

  try {
    return await callback();
  } finally {
    release();
  }
}

async function getCachedSessionCredentials() {
  const cacheFilename = getCacheFilename();

  let data: string;
  try {
    data = await readFile(cacheFilename).then((buffer) => buffer.toString());
  } catch (e) {
    if (!isFileNotFoundError(e)) {
      throw e;
    }
    logger.debug(`No cached credentials found.`, cacheFilename);
    return undefined;
  }

  try {
    logger.debug(`Found cached credentials`, { cacheFilename });

    const creds = z
      .object({
        AccessKeyId: z.string(),
        SecretAccessKey: z.string(),
        SessionToken: z.string(),
        Expiration: z
          .string()
          .datetime()
          .transform((s) => new Date(s)),
      })
      .parse(JSON.parse(data));

    if (creds.Expiration.getTime() < Date.now()) {
      logger.info(`Cached credentials expired as of ${creds.Expiration}.`);
      return undefined;
    }

    return creds;
  } catch (e) {
    logger.warn(`Invalid cached credentials.`, e);
  }
}

function get1pAwsKeys(): AwsKeys {
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
    logger.error(program.helpInformation());
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

async function getNewSessionCredentials(keys: AwsKeys) {
  const sts = new STS({
    credentials: {
      accessKeyId: keys.accessKeyId,
      secretAccessKey: keys.secretAccessKey,
    },
  });

  let creds: Credentials | undefined;

  if (options.roleArn == null) {
    const response = await sts.getSessionToken({
      SerialNumber: keys.mfaSerial,
      TokenCode: keys.totp,
      DurationSeconds: options.duration,
    });

    creds = response.Credentials;
  } else {
    const response = await sts.assumeRole({
      SerialNumber: keys.mfaSerial,
      TokenCode: keys.totp,
      RoleArn: options.roleArn,
      RoleSessionName: options.roleSessionName,
      DurationSeconds: options.duration,
    });

    creds = response.Credentials;
  }

  if (creds == null) {
    throw new Error(`Failed to generate AWS session credentials.`);
  }

  return creds;
}

async function generateCredentials() {
  logger.info(`Generating credentials`, options);

  const creds = await withLockInternal(async () => {
    logger.debug(`Lock acquired`);

    let maybeCreds: Credentials | undefined;

    for (let i = 0; i < 2 && maybeCreds == null; i++) {
      if (options.cache) {
        maybeCreds = await getCachedSessionCredentials();
        if (maybeCreds != null) return maybeCreds;
      } else {
        logger.debug("Skipping cache");
      }

      const keys = get1pAwsKeys();
      try {
        maybeCreds = await getNewSessionCredentials(keys);
      } catch (e) {
        if (!isInvalidMfaError(e) || i > 0) {
          throw e;
        }

        //
        // If the credential process was called multiple times quickly, it might have tried to re-use
        // the same one-time code. Wait for it to cycle then try again.
        //
        const pauseSeconds = getTotpSecondsRemaining() + 3;
        logger.warn(
          `Invalid MFA code on first attempt. Pausing for ${pauseSeconds} seconds to try again in case of reuse.`,
        );
        await new Promise((resolve) =>
          setTimeout(resolve, pauseSeconds * 1000),
        );
      }
    }

    assert.ok(maybeCreds != null);
    await writeFile(getCacheFilename(), JSON.stringify(maybeCreds, null, 2));
    return maybeCreds;
  });

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

try {
  await generateCredentials();
} catch (e) {
  console.error(`Failed to generate credentials.`);
  console.error(`Debug log saved to ${logFilename}.`);

  logger.error(e);

  if (!process.stdout.isTTY) {
    notifier.on("click", () => {
      exec(`open ${logFilename}`).unref();
      process.exit(1);
    });

    notifier.on("timeout", () => process.exit(1));

    notifier.notify({
      message:
        (e instanceof Error ? e.message : undefined) ??
        "Error generating credentials",
      title: "OPAWS",
      actions: "View Log",
      wait: true,
    });
  } else {
    process.exit(1);
  }
}
