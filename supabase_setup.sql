-- ============================================================
-- NSBIO Tech - Configuration Supabase (à exécuter UNE fois)
-- Supabase > SQL Editor > New query > coller tout ce fichier > Run
-- ============================================================

-- 1) PROFILS : un profil par compte, avec son rôle
--    resp = Responsable (tout)   op = Opérateur (ajoute des pesées)   aud = Auditeur (lecture seule)
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  name       text,
  role       text not null default 'aud' check (role in ('resp','op','aud')),
  created_at timestamptz default now()
);
alter table public.profiles enable row level security;

-- Rôle de la personne connectée (security definer : évite la récursion des règles)
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

drop policy if exists "profil_lecture"  on public.profiles;
drop policy if exists "profil_gestion"  on public.profiles;
create policy "profil_lecture" on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() = 'resp');
create policy "profil_gestion" on public.profiles for update to authenticated
  using (public.my_role() = 'resp') with check (public.my_role() = 'resp');

-- Création automatique du profil à chaque nouveau compte :
-- le TOUT PREMIER compte créé devient Responsable, les suivants Auditeur (le moins de droits).
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, name, role)
  values (
    new.id, new.email, split_part(new.email, '@', 1),
    case when exists (select 1 from public.profiles where role = 'resp') then 'aud' else 'resp' end
  );
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 2) DONNÉES : lots, pesées (w), dépenses (c), produits, matières, numérotation, abonnement
create table if not exists public.store (
  key        text primary key,
  data       jsonb not null default 'null'::jsonb,
  updated_at timestamptz default now(),
  updated_by uuid default auth.uid()
);
alter table public.store enable row level security;

drop policy if exists "store_lecture"   on public.store;
drop policy if exists "store_insertion" on public.store;
drop policy if exists "store_maj"       on public.store;

-- Lecture : tout compte ayant un profil (Responsable, Opérateur, Auditeur)
create policy "store_lecture" on public.store for select to authenticated
  using (public.my_role() is not null);

-- Écriture : le Responsable partout ; l'Opérateur uniquement sur les pesées ('w')
create policy "store_insertion" on public.store for insert to authenticated
  with check (public.my_role() = 'resp' or (public.my_role() = 'op' and key = 'w'));
create policy "store_maj" on public.store for update to authenticated
  using      (public.my_role() = 'resp' or (public.my_role() = 'op' and key = 'w'))
  with check (public.my_role() = 'resp' or (public.my_role() = 'op' and key = 'w'));
-- Aucune règle de suppression : personne ne peut effacer les données depuis l'application.

-- Garde-fou : l'Opérateur peut AJOUTER des pesées mais pas modifier ni retirer celles qui existent.
create or replace function public.store_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.updated_at := now();
  new.updated_by := auth.uid();
  if public.my_role() = 'op' and not (new.data @> old.data) then
    raise exception 'Un opérateur peut seulement ajouter des pesées.';
  end if;
  return new;
end $$;

drop trigger if exists store_guard on public.store;
create trigger store_guard before update on public.store
  for each row execute function public.store_guard();

-- ============================================================
-- ENSUITE : créer les comptes (Authentication > Users > Add user,
-- cocher "Auto Confirm User"), puis attribuer les rôles :
--
--   update public.profiles set role = 'op',  name = 'Nom Opérateur' where email = 'operateur@exemple.com';
--   update public.profiles set role = 'aud', name = 'Nom Auditeur'  where email = 'auditeur@exemple.com';
--
-- Le premier compte créé (le vôtre) est automatiquement Responsable.
-- ============================================================
