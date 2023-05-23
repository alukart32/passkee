CREATE TABLE IF NOT EXISTS "users" (
    id uuid  PRIMARY KEY,
    username VARCHAR NOT NULL UNIQUE CHECK(LENGTH(username) > 0),
    password VARCHAR NOT NULL CHECK(LENGTH(password) > 0)
);

CREATE TYPE "blob_object_typ" AS ENUM (
  'TEXT',
  'BIN'
);

CREATE TABLE IF NOT EXISTS "blob_objects" (
  id      uuid PRIMARY KEY,
  user_id uuid NOT NULL,
	name    VARCHAR NOT NULL UNIQUE CHECK(LENGTH(name) > 0),
	typ     blob_object_typ NOT NULL,
  blob    BYTEA NOT NULL,
	notes   BYTEA
);

CREATE TABLE IF NOT EXISTS "passwords" (
  id      uuid PRIMARY KEY,
  user_id uuid NOT NULL,
	name    VARCHAR NOT NULL UNIQUE CHECK(LENGTH(name) > 0),
	data    BYTEA NOT NULL CHECK(LENGTH(data) > 0),
	notes   BYTEA
);

CREATE TABLE IF NOT EXISTS "credit_cards" (
  id      uuid PRIMARY KEY,
  user_id uuid NOT NULL,
	name    VARCHAR NOT NULL UNIQUE CHECK(LENGTH(name) > 0),
	data    BYTEA NOT NULL CHECK(LENGTH(data) > 0),
	notes   BYTEA
);

ALTER TABLE "blob_objects" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "passwords" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "credit_cards" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");