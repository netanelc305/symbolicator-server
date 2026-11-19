-- The symbols database, built from `ipsw symbols --json` output.

-- One loaded IPSW. sha1 is of the .ipsw file: the scanner's "id".
CREATE TABLE IF NOT EXISTS ipsw (
    id INTEGER NOT NULL,
    sha1 VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    build VARCHAR NOT NULL,
    platform VARCHAR,
    devices JSON,
    PRIMARY KEY (id),
    UNIQUE (sha1)
);

-- One UUID: the binary itself, which owns the symbols. A UUID is one binary, so all its copies
-- have the same functions. Every scan of a UUID adds to the same symbols.
CREATE TABLE IF NOT EXISTS macho (
    id INTEGER NOT NULL,
    uuid VARCHAR NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (uuid)
);

-- Every distinct symbol name, stored once. Names are found by hash (the first 8 bytes of their
-- sha1), not by their text: an index on the text would store every name a second time. Two names
-- can share a hash, so the text is still compared.
CREATE TABLE IF NOT EXISTS name (
    id INTEGER NOT NULL,
    text VARCHAR NOT NULL,
    hash INTEGER NOT NULL,
    PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_name_hash ON name (hash);

-- One dyld_shared_cache in an IPSW.
CREATE TABLE IF NOT EXISTS dsc (
    id INTEGER NOT NULL,
    ipsw_id INTEGER NOT NULL,
    uuid VARCHAR NOT NULL,
    shared_region_start INTEGER NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (ipsw_id) REFERENCES ipsw (id)
);
CREATE INDEX IF NOT EXISTS ix_dsc_uuid ON dsc (uuid);

-- One distinct copy of a binary (kernel, kext, dylib, macho) and where it sits. Copies of a UUID
-- sit at different addresses (a dylib in every device's cache, dyld also on disk, a kext in the
-- kernelcache and as a .kext file), so symbols are stored as offsets: address = offset_base + offset.
-- offset_base is usually text_start, but a standalone .kext's text_start is its __TEXT while the
-- kernelcache's copy is measured from __TEXT_EXEC. NULL: this copy's functions could not be lined
-- up with the UUID's stored ones, so it has no symbols.
CREATE TABLE IF NOT EXISTS image (
    id INTEGER NOT NULL,
    macho_id INTEGER NOT NULL,
    kind VARCHAR NOT NULL,
    path VARCHAR NOT NULL,
    text_start INTEGER NOT NULL,
    text_size INTEGER NOT NULL,
    dsc_uuid VARCHAR,
    cpu VARCHAR,
    arch VARCHAR,
    kernel_version VARCHAR,
    offset_base INTEGER,
    PRIMARY KEY (id),
    FOREIGN KEY (macho_id) REFERENCES macho (id)
);
CREATE INDEX IF NOT EXISTS image_by_dsc ON image (dsc_uuid, text_start);
CREATE INDEX IF NOT EXISTS ix_image_macho_id ON image (macho_id);

-- One function of a UUID. name_id NULL: an unnamed function (the scanner's func_<address>).
-- WITHOUT ROWID: the rows are stored in primary key order, so the table is its own index for
-- "the functions of this UUID near this offset", and no separate index copies its columns.
CREATE TABLE IF NOT EXISTS symbol (
    macho_id INTEGER NOT NULL,
    "offset" INTEGER NOT NULL,
    size INTEGER NOT NULL,
    name_id INTEGER,
    PRIMARY KEY (macho_id, "offset"),
    FOREIGN KEY (macho_id) REFERENCES macho (id),
    FOREIGN KEY (name_id) REFERENCES name (id)
) WITHOUT ROWID;

-- Which IPSWs have which images (IPSWs of one build share almost all of them).
CREATE TABLE IF NOT EXISTS ipsw_image (
    ipsw_id INTEGER NOT NULL,
    image_id INTEGER NOT NULL,
    PRIMARY KEY (ipsw_id, image_id),
    FOREIGN KEY (ipsw_id) REFERENCES ipsw (id),
    FOREIGN KEY (image_id) REFERENCES image (id)
) WITHOUT ROWID;

-- Which kext images are in which fileset kernelcache. Some reports (stackshots) give kernel frames
-- as offsets into the whole kernelcache; its functions are in its kexts. An address alone is not
-- enough: an IPSW has a kernelcache per device (and a research one), all at the same address,
-- with different kexts in them.
CREATE TABLE IF NOT EXISTS kernelcache_kext (
    kernelcache_id INTEGER NOT NULL,
    image_id INTEGER NOT NULL,
    PRIMARY KEY (kernelcache_id, image_id),
    FOREIGN KEY (kernelcache_id) REFERENCES macho (id),
    FOREIGN KEY (image_id) REFERENCES image (id)
) WITHOUT ROWID;
