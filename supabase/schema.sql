-- Supabase/Postgres schema for Sunbeth Ack Portal (minimal tables required by current API)
-- Run this in Supabase SQL Editor before switching DB_DRIVER=pg

create table if not exists businesses (
  id serial primary key,
  name text not null,
  code text,
  isactive integer default 1,
  description text
);

create table if not exists batches (
  id serial primary key,
  name text not null,
  startdate text,
  duedate text,
  status integer default 1,
  description text
);

create table if not exists documents (
  id serial primary key,
  batchid integer not null references batches(id) on delete cascade,
  title text not null,
  url text not null,
  version integer default 1,
  requiressignature integer default 0,
  driveid text,
  itemid text,
  source text,
  localfileid integer,
  localurl text
);
create unique index if not exists ux_documents_batch_url on documents(batchid, url);
create index if not exists idx_documents_batch on documents(batchid);

create table if not exists recipients (
  id serial primary key,
  batchid integer not null references batches(id) on delete cascade,
  businessid integer references businesses(id) on delete set null,
  "user" text,
  email text,
  displayname text,
  department text,
  jobtitle text,
  location text,
  primarygroup text
);
create unique index if not exists ux_recipients_batch_email on recipients(batchid, lower(email));
create index if not exists idx_recipients_batch on recipients(batchid);

create table if not exists acks (
  id serial primary key,
  batchid integer not null references batches(id) on delete cascade,
  documentid integer not null references documents(id) on delete cascade,
  email text not null,
  acknowledged integer default 1,
  ackdate text
);
create index if not exists idx_acks_batch on acks(batchid);
create index if not exists idx_acks_doc on acks(documentid);

create table if not exists app_settings (
  key text primary key,
  value text not null
);

-- Admin notifications emails used by UI
create table if not exists notification_emails (
  email text primary key
);

create table if not exists roles (
  id serial primary key,
  email text not null,
  role text not null,
  createdat text
);
create unique index if not exists ux_roles_email_role on roles(lower(email), role);

-- Minimal uploads table (referenced by endpoints; full columns optional)
create table if not exists uploaded_files (
  id serial primary key,
  original_name text,
  stored_name text,
  rel_path text,
  size integer,
  mime text,
  sha256 text,
  uploaded_at text,
  uploaded_by text,
  source_type text,
  source_url text,
  driveid text,
  itemid text
);
create unique index if not exists ux_uploaded_files_sha on uploaded_files(sha256);

-- Seed convenience
insert into businesses (name, code, isactive, description)
  values ('Default Business','DEF',1,'Auto-created')
  on conflict do nothing;

-- app flag used by frontend
insert into app_settings(key, value) values ('external_support_enabled','0')
  on conflict (key) do update set value = excluded.value;
