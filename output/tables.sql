CREATE TABLE annotation(
    addr TEXT,
    router TEXT,
    asn INT,
    org TEXT,
    conn_asn INT,
    conn_org TEXT,
    rtype INT,
    itype INT
);

CREATE TABLE ixp(
    addr TEXT,
    router TEXT,
    asn INT,
    org TEXT,
    conn_asn INT,
    conn_org TEXT,
    pid INT
);

CREATE TABLE excluded (
    addr    TEXT,
    asn     INTEGER,
    org     TEXT,
    reason  TEXT
);