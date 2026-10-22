-- شغّل الملف كله مرة واحدة في Supabase > SQL Editor

alter table profiles add column if not exists teacher_note text;
alter table profiles add column if not exists blocked boolean default false;

create table if not exists lessons (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  grade text not null,
  video_url text,
  exam_url text,
  sort_order int default 0,
  created_at timestamptz default now()
);
create table if not exists codes (
  code text primary key,
  lesson_id uuid references lessons(id) on delete cascade,
  used_by uuid references profiles(id),
  used_at timestamptz
);
create table if not exists unlocks (
  student_id uuid references profiles(id) on delete cascade,
  lesson_id uuid references lessons(id) on delete cascade,
  unlocked_at timestamptz default now(),
  primary key (student_id, lesson_id)
);
create table if not exists views (
  id bigint generated always as identity primary key,
  student_id uuid references profiles(id) on delete cascade,
  lesson_id uuid references lessons(id) on delete cascade,
  viewed_at timestamptz default now()
);
create table if not exists exams (
  student_id uuid references profiles(id) on delete cascade,
  lesson_id uuid references lessons(id) on delete cascade,
  submitted boolean default false,
  score text,
  primary key (student_id, lesson_id)
);

create or replace function is_teacher() returns boolean
language sql security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'teacher');
$$;

create or replace function is_parent_of(sid uuid) returns boolean
language sql security definer set search_path = public as $$
  select exists (
    select 1 from profiles s, profiles p
    where s.id = sid and p.id = auth.uid() and p.role = 'parent'
      and s.parent_phone = p.phone);
$$;

create or replace function redeem_code(p_code text, p_lesson uuid)
returns text language plpgsql security definer set search_path = public as $$
declare c codes%rowtype;
begin
  select * into c from codes where code = p_code and lesson_id = p_lesson for update;
  if not found then return 'invalid'; end if;
  if c.used_by is not null then return 'used'; end if;
  update codes set used_by = auth.uid(), used_at = now() where code = p_code;
  insert into unlocks(student_id, lesson_id) values (auth.uid(), p_lesson) on conflict do nothing;
  return 'ok';
end $$;

alter table profiles enable row level security;
alter table lessons enable row level security;
alter table codes enable row level security;
alter table unlocks enable row level security;
alter table views enable row level security;
alter table exams enable row level security;

-- profiles (احذف أي سياسات قديمة على profiles من Authentication > Policies)
drop policy if exists p_select on profiles;
drop policy if exists p_insert on profiles;
drop policy if exists p_teacher_update on profiles;
create policy p_select on profiles for select
  using (id = auth.uid() or is_teacher() or is_parent_of(id));
create or replace function teacher_exists() returns boolean
language sql security definer set search_path = public as $$
  select exists (select 1 from profiles where role = 'teacher');
$$;
grant execute on function teacher_exists() to anon, authenticated;

-- الطالب وولي الأمر يسجلوا دايماً، والمستر مرة واحدة بس (لو مفيش مستر)
create policy p_insert on profiles for insert
  with check (id = auth.uid() and (
    role in ('student','parent') or (role = 'teacher' and not teacher_exists())));
create policy p_teacher_update on profiles for update
  using (is_teacher()) with check (is_teacher());

drop policy if exists l_read on lessons;
drop policy if exists l_teacher on lessons;
create policy l_read on lessons for select using (auth.role() = 'authenticated');
create policy l_teacher on lessons for all using (is_teacher()) with check (is_teacher());

drop policy if exists c_teacher on codes;
create policy c_teacher on codes for all using (is_teacher()) with check (is_teacher());

drop policy if exists u_read on unlocks;
create policy u_read on unlocks for select
  using (student_id = auth.uid() or is_teacher() or is_parent_of(student_id));

drop policy if exists v_read on views;
drop policy if exists v_insert on views;
create policy v_read on views for select
  using (student_id = auth.uid() or is_teacher() or is_parent_of(student_id));
create policy v_insert on views for insert with check (student_id = auth.uid());

drop policy if exists e_read on exams;
drop policy if exists e_write on exams;
drop policy if exists e_update on exams;
create policy e_read on exams for select
  using (student_id = auth.uid() or is_teacher() or is_parent_of(student_id));
create policy e_write on exams for insert
  with check (student_id = auth.uid() or is_teacher());
create policy e_update on exams for update
  using (is_teacher() or student_id = auth.uid()) with check (is_teacher() or student_id = auth.uid());

-- تخزين الفيديوهات (خاص)
insert into storage.buckets (id, name, public) values ('videos','videos',false)
  on conflict (id) do nothing;
drop policy if exists vid_read on storage.objects;
drop policy if exists vid_teacher on storage.objects;
create policy vid_read on storage.objects for select
  using (bucket_id = 'videos' and auth.role() = 'authenticated');
create policy vid_teacher on storage.objects for all
  using (bucket_id = 'videos' and is_teacher())
  with check (bucket_id = 'videos' and is_teacher());


-- ============ إضافات: حد الأجهزة + نسيت كلمة السر (شغّلها بعد الباقي) ============
create extension if not exists pgcrypto with schema extensions;

create table if not exists devices (
  user_id uuid references profiles(id) on delete cascade,
  device_id text,
  last_seen timestamptz default now(),
  primary key (user_id, device_id)
);
alter table devices enable row level security;
drop policy if exists d_teacher on devices;
create policy d_teacher on devices for select using (is_teacher());

create table if not exists reset_requests (
  id bigint generated always as identity primary key,
  phone text not null,
  created_at timestamptz default now()
);
alter table reset_requests enable row level security;
drop policy if exists rr_insert on reset_requests;
drop policy if exists rr_teacher on reset_requests;
create policy rr_insert on reset_requests for insert to anon, authenticated with check (true);
create policy rr_teacher on reset_requests for all using (is_teacher()) with check (is_teacher());

create or replace function register_device(p_device text) returns text
language plpgsql security definer set search_path = public as $$
declare r text; n int;
begin
  select role into r from profiles where id = auth.uid();
  if r is null then return 'noprofile'; end if;
  if r = 'teacher' then return 'ok'; end if;
  if exists (select 1 from devices where user_id = auth.uid() and device_id = p_device) then
    update devices set last_seen = now() where user_id = auth.uid() and device_id = p_device;
    return 'ok';
  end if;
  select count(*) into n from devices where user_id = auth.uid();
  if n >= 2 then return 'limit'; end if;
  insert into devices(user_id, device_id) values (auth.uid(), p_device);
  return 'ok';
end $$;

create or replace function admin_clear_devices(p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_teacher() then raise exception 'not allowed'; end if;
  delete from devices where user_id = p_user;
end $$;

create or replace function admin_reset_password(p_user uuid, p_pass text) returns void
language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not is_teacher() then raise exception 'not allowed'; end if;
  if length(p_pass) < 6 then raise exception 'short password'; end if;
  update auth.users set encrypted_password = crypt(p_pass, gen_salt('bf')), updated_at = now() where id = p_user;
end $$;
