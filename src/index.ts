import { readFile, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

import { Item, item } from "@1password/op-js";
import { Credentials, STS } from "@aws-sdk/client-sts";
import { keyBy } from "lodash-es";
import { z } from "zod";

import { Command } from "@commander-js/extra-typings";

const program = new Command()
  .option("-r, --role-arn <role ARN>", "Specify a role to assume.")
  .option(
    "-s, --role-session-name <role session name>",
    "Specify a session name for the assumed role session.",
  )
  .option(
    "-a, --op-account <op account name>",
    "Specify the OnePassword account name.",
  )
  .option(
    "-v, --op-vault <op vault name>",
    "Specify the OnePassword vault name.",
  )
  .option(
    "-i, --op-item <op item name>",
    "Specify the OnePassword item name.",
    "AWS Access Key",
  )
  .option("--no-cache", "Do not use cached credentials if they exist.");

async function index() {
  const options = program.parse(process.argv).opts();

  const { opAccount, opVault, opItem, roleArn, roleSessionName } = options;

  const cacheFileBaseName = sanitizeFilename(
    [
      opAccount ?? "default",
      opVault ?? "default",
      opItem,
      roleArn ?? "default",
      roleSessionName ?? "default",
    ].join("-"),
  );

  let creds: Credentials | undefined;

  const cacheFileName = join(tmpdir(), `${cacheFileBaseName}.json`);

  try {
    creds = await readFile(cacheFileName).then((data) =>
      JSON.parse(data.toString()),
    );
    if (creds?.Expiration != null) {
      const now = new Date();
      const expiration = new Date(creds.Expiration);
      if (expiration <= now) {
        console.log("Credentials expired.");
        creds = undefined;
      }
    }
  } catch {
    //
    // Probably cache file does not exist, should validate that though
    // In the meantime resetting to undefined in case it exists but is corrupted
    //
    creds = undefined;
  }

  if (creds == null) {
    const opResult = item.get(opItem, {
      account: opAccount,
      vault: opVault,
    }) as Item;

    const parsed = parseItem(opResult);

    const sts = new STS({
      credentials: {
        accessKeyId: parsed.accessKeyId,
        secretAccessKey: parsed.secretAccessKey,
      },
    });

    if (roleArn == null) {
      const response = await sts.getSessionToken({
        SerialNumber: parsed.mfaSerial,
        TokenCode: parsed.totp,
      });

      creds = response.Credentials;
    } else {
      const response = await sts.assumeRole({
        SerialNumber: parsed.mfaSerial,
        TokenCode: parsed.totp,
        RoleArn: roleArn,
        RoleSessionName: roleSessionName,
      });

      creds = response.Credentials;
    }
  }

  if (creds == null) {
    throw new Error("Failed to generate credentials.");
  }

  await writeFile(cacheFileName, JSON.stringify(creds, null, 2));

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

function parseItem(item: Item) {
  const fields = keyBy(item.fields, "label");

  const baseFields = z
    .object({
      "access key id": z.object({
        type: z.literal("STRING"),
        value: z.string(),
      }),
      "secret access key": z.object({
        type: z.literal("CONCEALED"),
        value: z.string(),
      }),
    })
    .parse(fields);

  const totpFields = z
    .object({
      "mfa serial": z.object({
        type: z.literal("STRING"),
        value: z.string(),
      }),
      "one-time password": z.object({
        type: z.literal("OTP"),
        totp: z.string(),
      }),
    })
    .safeParse(fields);

  if (totpFields.success) {
    return {
      accessKeyId: baseFields["access key id"].value,
      secretAccessKey: baseFields["secret access key"].value,
      mfaSerial: totpFields.data["mfa serial"].value,
      totp: totpFields.data["one-time password"].totp,
    };
  }

  return {
    accessKeyId: baseFields["access key id"].value,
    secretAccessKey: baseFields["secret access key"].value,
    mfaSerial: undefined,
    totp: undefined,
  };
}

function sanitizeFilename(filename: string) {
  return filename.replace(/[/\\?%*:|"<>]/g, "-");
}

index();
