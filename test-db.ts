import Database from "better-sqlite3";
try {
  const db = new Database("test.db");
  db.exec("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY)");
  console.log("SQLite works!");
  process.exit(0);
} catch (err) {
  console.error("SQLite failed:", err);
  process.exit(1);
}
