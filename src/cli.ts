import { Command } from "commander";
import notifier from "node-notifier";

import { command as authenticateCommand } from "./authenticate.js";
import { command as clearCommand } from "./clear.js";

const program = new Command();
program.addCommand(authenticateCommand as Command, { isDefault: true });
program.addCommand(
  new Command("util")
    .addCommand(clearCommand as Command)
    .addCommand(
      new Command("notify").action(() => {
        notifier.notify({
          message: "Test notification",
          title: "OPAWS",
          actions: "Acknowledge",
          wait: true,
        });

        notifier.on("click", () => {
          console.log("Notification was acknowledged 😀");
        });

        notifier.on("timeout", () => {
          console.log("Notification was ignored or dismissed 😔");
        });
      }),
    )
    .description("Administrative utility commands."),
);

program.parse(process.argv);
