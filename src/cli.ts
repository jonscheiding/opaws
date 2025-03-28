import { Command } from "commander";

import { command as authenticateCommand } from "./authenticate.js";

const program = new Command();
program.addCommand(authenticateCommand as Command, { isDefault: true });

program.parse(process.argv);
