import { exec } from "child_process";
import { closeSync, openSync } from "fs";
import { readFile, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

import op, { Item } from "@1password/op-js";
import { Credentials, STS } from "@aws-sdk/client-sts";
import { lock } from "cross-process-lock";
import { keyBy } from "lodash-es";
import winston from "winston";
import { z } from "zod";

import { Command } from "@commander-js/extra-typings";
import notifier from "node-notifier";

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

const logFilename = join(tmpdir(), `opaws-${Date.now()}-${process.pid}.log`);

const logger = winston.createLogger({
  level: "debug",
  format: winston.format.simple(),
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

function getCacheFilename() {
  const { opAccount, opVault, opItem, roleArn, roleSessionName } = options;

  const cacheKey = [
    opAccount ?? "default",
    opVault ?? "default",
    opItem,
    roleArn ?? "default",
    roleSessionName ?? "default",
  ].join("-");

  return join(tmpdir(), sanitizeFilename(`${cacheKey}.json`));
}

async function lockInternal() {
  const lockFileName = join(tmpdir(), "op-credential-process.lock");

  //
  // ensure lock file exists - cross-process-lock doesn't create it for you
  //
  closeSync(openSync(lockFileName, "w"));

  return await lock(lockFileName);
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
    });

    creds = response.Credentials;
  } else {
    const response = await sts.assumeRole({
      SerialNumber: keys.mfaSerial,
      TokenCode: keys.totp,
      RoleArn: options.roleArn,
      RoleSessionName: options.roleSessionName,
    });

    creds = response.Credentials;
  }

  if (creds == null) {
    throw new Error(`Failed to generate AWS session credentials.`);
  }

  return creds;
}

async function generateCredentials() {
  let creds: Credentials | undefined;

  const release = await lockInternal();

  try {
    if (options.cache) {
      creds = await getCachedSessionCredentials();
    }

    if (creds == null) {
      const keys = get1pAwsKeys();
      //
      // Early release so we don't block while actually calling AWS API
      //
      await release();

      creds = await getNewSessionCredentials(keys);
    }
  } finally {
    await release();
  }

  await writeFile(getCacheFilename(), JSON.stringify(creds, null, 2));

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
  logger.error(e);

  if (!process.stdout.isTTY) {
    notifier.on("click", () => {
      exec(`open ${logFilename}`).unref();
    });

    notifier.notify({
      message: "Error generating credentials",
      title: "OP Credential Process",
      actions: "View Log",
      wait: true,
    });
  }

  console.error(`Failed to generate credentials.`);
  console.error(`Debug log saved to ${logFilename}.`);
}
