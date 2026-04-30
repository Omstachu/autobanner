"""One-time script: seed the blocked_users table from the payments table. Delete after use."""
import db
import build_blocked_list as bbl

db.init_db()
bbl.build_from_db()
print("Done — blocked users seeded into database")
