import { exec, spawn } from "child_process";
import { promisify } from "util";

import { logger } from "./logger.js";

const execAsync = promisify(exec);

export type NotifyOptions = {
  title: string;
  message: string;
  actions?: string[];
  timeout?: number;
};

export type NotifyResult =
  | { kind: "action"; action: string }
  | { kind: "contentClicked" }
  | { kind: "closed" }
  | { kind: "timeout" }
  | { kind: "other"; activationType: string };

const ALERTER_BIN = "alerter";

let alerterAvailable: boolean | undefined;

async function isAlerterAvailable(): Promise<boolean> {
  if (alerterAvailable !== undefined) return alerterAvailable;

  try {
    await execAsync(`command -v ${ALERTER_BIN}`);
    alerterAvailable = true;
  } catch {
    alerterAvailable = false;
    logger.debug(
      `'${ALERTER_BIN}' was not found on PATH; notifications are disabled.`,
    );
  }

  return alerterAvailable;
}

export async function notify(
  options: NotifyOptions,
): Promise<NotifyResult | undefined> {
  if (!(await isAlerterAvailable())) return undefined;

  const args = [
    "--title",
    options.title,
    "--message",
    options.message,
    "--json",
  ];

  if (options.actions?.length) {
    args.push("--actions", options.actions.join(","));
  }

  if (options.timeout != null) {
    args.push("--timeout", String(options.timeout));
  }

  const output = await new Promise<string>((resolve, reject) => {
    const child = spawn(ALERTER_BIN, args);
    let stdout = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", () => resolve(stdout));
  });

  let parsed: { activationType?: string; activationValue?: string };
  try {
    parsed = JSON.parse(output);
  } catch (e) {
    logger.warn(`Could not parse alerter output: ${output}`, e);
    return undefined;
  }

  switch (parsed.activationType) {
    case "actionClicked":
      return { kind: "action", action: parsed.activationValue ?? "" };
    case "contentClicked":
      return { kind: "contentClicked" };
    case "closed":
      return { kind: "closed" };
    case "timeout":
      return { kind: "timeout" };
    default:
      return { kind: "other", activationType: parsed.activationType ?? "" };
  }
}
