create table account (
  id            integer primary key,
  creation_time integer not null
);

create table account_pass (
  account_id integer not null,
  pass       varchar not null
);

create table nick (
  nick       varchar primary key,
  account_id integer not null
);
