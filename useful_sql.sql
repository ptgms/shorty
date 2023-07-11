-- The Database Scheme has to be Postgres!

-- Create links table
CREATE TABLE IF NOT EXISTS shorty_links (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    short_code TEXT NOT NULL UNIQUE,
    clicks INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL DEFAULT NOW()
);