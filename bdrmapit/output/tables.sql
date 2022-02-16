CREATE TABLE annotation(
    addr TEXT,
    router TEXT,
    asn INT,
    org TEXT,
    conn_asn INT,
    conn_org TEXT,
    echo BOOLEAN,
    nexthop BOOLEAN,
    phop BOOLEAN,
    rtype INT,
    itype INT,
    iasn INT
);

CREATE TABLE ixp(
    addr TEXT,
    router TEXT,
    asn INT,
    org TEXT,
    conn_asn INT,
    conn_org TEXT,
    pid INT,
    nexthop BOOLEAN
);

CREATE TABLE link(
    addr TEXT,
    router TEXT,
    asn INT,
    org TEXT,
    conn_asn INT,
    conn_org TEXT,
    ixp boolean
);

CREATE TABLE excluded (
    addr    TEXT,
    asn     INTEGER,
    org     TEXT,
    reason  TEXT
);

CREATE TABLE cache(
    addr TEXT,
    router TEXT,
    asn INT,
    org TEXT,
    conn_asn INT,
    conn_org TEXT,
    ixp boolean
);
