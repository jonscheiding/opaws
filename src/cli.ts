import { Command } from "commander";

import { command as authenticateCommand } from "./authenticate.js";
import { command as clearCommand } from "./clear.js";
import { notify } from "./notifier.js";

const program = new Command();
program.addCommand(authenticateCommand as Command, { isDefault: true });
program.addCommand(
  new Command("util")
    .addCommand(clearCommand as Command)
    .addCommand(
      new Command("notify").action(async () => {
        const result = await notify({
          title: "OPAWS",
          message: "Test notification",
          actions: ["Acknowledge"],
        });

        if (result === undefined) {
          console.log(
            "'alerter' is not installed; notifications are disabled.",
          );
        } else if (result.kind === "action") {
          console.log("Notification was acknowledged 😀");
        } else {
          console.log("Notification was ignored or dismissed 😔");
        }
      }),
    )
    .description("Administrative utility commands."),
);

program.parse(process.argv);
