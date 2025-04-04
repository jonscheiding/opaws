import { Command } from "commander";

import { command as authenticateCommand } from "./authenticate.js";
import { command as clearCommand } from "./clear.js";

const program = new Command();
program.addCommand(authenticateCommand as Command, { isDefault: true });
program.addCommand(
  new Command("util")
    .addCommand(clearCommand as Command)
    .description("Administrative utility commands."),
);

program.parse(process.argv);
