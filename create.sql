create table account (
  id            integer primary key,
  creation_time integer not null,
  name          varchar not null
);

create table account_pass (
  account_id integer not null,
  pass       varchar not null
);

create table nick (
  nick       varchar primary key,
  account_id integer not null
);

create table channel (
  id            integer primary key,
  name          varchar not null,
  creation_time integer not null,
  mode          varchar not null,
  topic         varchar
);

create unique index channel_name on channel (name);
