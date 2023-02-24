-- Your SQL goes here
CREATE TABLE users (
  id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  name VARCHAR NOT NULL,
  email TEXT NOT NULL,
  password VARCHAR NOT NULL
)
