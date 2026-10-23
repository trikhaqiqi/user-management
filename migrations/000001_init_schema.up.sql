-- Godigi user management schema.
-- Design notes are in README.md ("Database design").
--
-- Naming convention:
--   m_    master data: the account itself
--   sys_  system/security records created and consumed by the auth flows
-- Constraints and indexes are prefixed with their table's name. The code
-- matches on m_users_email_key.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE user_status AS ENUM ('pending_verification', 'active', 'deactivated');
CREATE TYPE otp_purpose AS ENUM ('email_verification', 'email_change');
CREATE TYPE session_revoke_reason AS ENUM (
    'logout', 'refresh_token_reuse', 'password_reset', 'password_change',
    'account_deactivated', 'account_inactive'
);

-- m_users: identity, credentials and account state.
-- citext makes the unique email constraint case-insensitive, so
-- Jane@x.com and jane@x.com can never both exist, even under concurrency.
CREATE TABLE m_users (
    id                  uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                varchar(100) NOT NULL,
    email               citext       NOT NULL,
    phone_number        varchar(16),
    password_hash       text         NOT NULL,
    status              user_status  NOT NULL DEFAULT 'pending_verification',
    email_verified_at   timestamptz,
    password_changed_at timestamptz  NOT NULL DEFAULT now(),
    deactivated_at      timestamptz,
    created_at          timestamptz  NOT NULL DEFAULT now(),
    updated_at          timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT m_users_email_key UNIQUE (email),
    CONSTRAINT m_users_email_length CHECK (char_length(email) <= 254),
    CONSTRAINT m_users_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT m_users_phone_e164 CHECK (phone_number IS NULL OR phone_number ~ '^\+[1-9][0-9]{7,14}$'),
    -- Only a pending account may lack a verification timestamp.
    CONSTRAINT m_users_verified_consistency CHECK (status = 'pending_verification' OR email_verified_at IS NOT NULL),
    CONSTRAINT m_users_deactivated_consistency CHECK ((status = 'deactivated') = (deactivated_at IS NOT NULL))
);

-- sys_otp_codes: one-time codes for registration and email change.
-- Only an HMAC of the code is stored. A code is live while consumed_at and
-- invalidated_at are both NULL, and the partial unique index allows one live
-- code per (user, purpose), so issuing a new code must retire the old one.
CREATE TABLE sys_otp_codes (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid        NOT NULL REFERENCES m_users (id) ON DELETE CASCADE,
    purpose        otp_purpose NOT NULL,
    code_hash      bytea       NOT NULL,
    target_email   citext,
    attempts       integer     NOT NULL DEFAULT 0,
    max_attempts   integer     NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    invalidated_at timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sys_otp_codes_hash_length CHECK (octet_length(code_hash) = 32),
    CONSTRAINT sys_otp_codes_attempts_range CHECK (attempts >= 0 AND attempts <= max_attempts),
    CONSTRAINT sys_otp_codes_target_email CHECK ((purpose = 'email_change') = (target_email IS NOT NULL)),
    CONSTRAINT sys_otp_codes_single_outcome CHECK (consumed_at IS NULL OR invalidated_at IS NULL)
);
CREATE UNIQUE INDEX sys_otp_codes_one_active_per_purpose
    ON sys_otp_codes (user_id, purpose) WHERE consumed_at IS NULL AND invalidated_at IS NULL;
-- Serves the resend cooldown and hourly-cap lookups.
CREATE INDEX sys_otp_codes_user_purpose_created_at ON sys_otp_codes (user_id, purpose, created_at DESC);

-- sys_password_reset_tokens: single-use reset tokens (SHA-256 of a 256-bit token).
CREATE TABLE sys_password_reset_tokens (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid        NOT NULL REFERENCES m_users (id) ON DELETE CASCADE,
    token_hash     bytea       NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    invalidated_at timestamptz,
    requested_ip   inet,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sys_password_reset_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT sys_password_reset_tokens_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT sys_password_reset_tokens_single_outcome CHECK (used_at IS NULL OR invalidated_at IS NULL)
);
CREATE UNIQUE INDEX sys_password_reset_tokens_one_active
    ON sys_password_reset_tokens (user_id) WHERE used_at IS NULL AND invalidated_at IS NULL;
CREATE INDEX sys_password_reset_tokens_user_created_at ON sys_password_reset_tokens (user_id, created_at DESC);

-- sys_sessions: one row per login. Access tokens carry the session id (sid), and
-- services check this row on every authenticated request, so revoking it
-- ends the session immediately.
CREATE TABLE sys_sessions (
    id             uuid                  PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid                  NOT NULL REFERENCES m_users (id) ON DELETE CASCADE,
    user_agent     varchar(512),
    ip_address     inet,
    expires_at     timestamptz           NOT NULL,
    last_used_at   timestamptz           NOT NULL DEFAULT now(),
    revoked_at     timestamptz,
    revoked_reason session_revoke_reason,
    created_at     timestamptz           NOT NULL DEFAULT now(),
    CONSTRAINT sys_sessions_revocation_consistency CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);
CREATE INDEX sys_sessions_user_id_active ON sys_sessions (user_id) WHERE revoked_at IS NULL;

-- sys_refresh_tokens: the rotation chain of a session. Each refresh marks the
-- presented token used and issues a successor. Presenting a used token again
-- is reuse, and revokes the whole session. The partial unique index keeps the
-- chain linear: at most one unused token per session.
CREATE TABLE sys_refresh_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id uuid        NOT NULL REFERENCES sys_sessions (id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sys_refresh_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT sys_refresh_tokens_hash_length CHECK (octet_length(token_hash) = 32)
);
CREATE UNIQUE INDEX sys_refresh_tokens_one_current_per_session ON sys_refresh_tokens (session_id) WHERE used_at IS NULL;
