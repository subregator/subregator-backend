
 CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL, tracking_started INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS resources (id TEXT PRIMARY KEY, prefix TEXT, family INTEGER NOT NULL, prefix_length INTEGER NOT NULL, address_count TEXT NOT NULL, start BLOB, end BLOB);
 CREATE INDEX IF NOT EXISTS resource_ranges ON resources(family,start,end);
 CREATE TABLE IF NOT EXISTS resource_providers(resource_id TEXT NOT NULL REFERENCES resources(id),provider_id TEXT NOT NULL,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,PRIMARY KEY(resource_id,provider_id));
 CREATE TABLE IF NOT EXISTS listings (id TEXT PRIMARY KEY,provider_id TEXT NOT NULL,resource_id TEXT NOT NULL REFERENCES resources(id),first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,removed_at INTEGER,appearances INTEGER NOT NULL,active INTEGER NOT NULL,payload BLOB NOT NULL,hash TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS listing_provider_active ON listings(provider_id,active);
 CREATE INDEX IF NOT EXISTS listing_resource ON listings(resource_id);
 CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,listing_id TEXT NOT NULL,provider_id TEXT NOT NULL,resource_id TEXT NOT NULL,next_resource_id TEXT NOT NULL,type TEXT NOT NULL,observed_at INTEGER NOT NULL,resource_reappeared INTEGER NOT NULL DEFAULT 0,before BLOB,after BLOB,changed_fields BLOB NOT NULL);
 CREATE INDEX IF NOT EXISTS events_listing ON events(listing_id,id);
 CREATE INDEX IF NOT EXISTS events_resource ON events(resource_id,id);
 CREATE INDEX IF NOT EXISTS events_next_resource ON events(next_resource_id,id);
 CREATE INDEX IF NOT EXISTS events_provider ON events(provider_id,id);
 CREATE TABLE IF NOT EXISTS polls(id INTEGER PRIMARY KEY AUTOINCREMENT,provider_id TEXT NOT NULL,observed_at INTEGER NOT NULL,complete INTEGER NOT NULL,count INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS check_cache(key TEXT PRIMARY KEY,payload BLOB NOT NULL,expires_at INTEGER NOT NULL,touched_at INTEGER NOT NULL);
 PRAGMA user_version=1;