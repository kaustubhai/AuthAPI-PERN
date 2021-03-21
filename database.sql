CREATE DATABASE "testAuth";

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE userBase ( 
    _id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL ,
    password VARCHAR(100) NOT NULL,
    pin VARCHAR(100) NOT NULL,
    created TIMESTAMP DEFAULT now()
 )