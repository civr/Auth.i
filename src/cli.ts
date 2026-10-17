import { runCommand } from './cli/commands.js';
import { loadConfig } from './config.js';
import { createDb } from './db/db.js';
import { runMigrations } from './db/migrate.js';
import { createServices } from './services.js';

const config = loadConfig();
const db = createDb(config.databaseUrl);
try {
  await runMigrations(db);
  console.log(await runCommand(createServices(config, db), process.argv.slice(2)));
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
} finally {
  await db.destroy();
}
