DROP TABLE IF EXISTS threat_control_map;
DROP TABLE IF EXISTS controls;
DROP TABLE IF EXISTS threats;

CREATE TABLE threats (
    id INTEGER PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    category VARCHAR(80) NOT NULL,
    weight NUMERIC(4,2) NOT NULL CHECK (weight >= 0 AND weight <= 1)
);

CREATE TABLE controls (
    id INTEGER PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    effectiveness NUMERIC(4,2) NOT NULL CHECK (effectiveness >= 0 AND effectiveness <= 1)
);

CREATE TABLE threat_control_map (
    threat_id INTEGER NOT NULL,
    control_id INTEGER NOT NULL,
    mapping_impact NUMERIC(4,2) NOT NULL CHECK (mapping_impact >= 0 AND mapping_impact <= 1),
    effectiveness NUMERIC(4,2) NOT NULL CHECK (effectiveness >= 0 AND effectiveness <= 1),
    control_name VARCHAR(150) NOT NULL,
    PRIMARY KEY (threat_id, control_id),
    CONSTRAINT fk_threat FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE,
    CONSTRAINT fk_control FOREIGN KEY (control_id) REFERENCES controls(id) ON DELETE CASCADE
);