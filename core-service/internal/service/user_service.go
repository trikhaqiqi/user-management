// Package service implements profile and account management.
package service

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"godigi/core-service/internal/dto"
	"godigi/core-service/internal/model"
	"godigi/core-service/internal/repository"
	"godigi/pkg/apperr"
	"godigi/pkg/database"
	"godigi/pkg/mailer"
	"godigi/pkg/otp"
	"godigi/pkg/security"
)

type UserService struct {
	pool *pgxpool.Pool
	otp  *otp.Manager
	mail *mailer.Async
}

func New(pool *pgxpool.Pool, otpCfg otp.Config, mail *mailer.Async) *UserService {
	return &UserService{pool: pool, otp: otp.NewManager(otpCfg), mail: mail}
}

// e164 matches the users_phone_e164 check constraint.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

var errWrongPassword = apperr.BadRequest("INVALID_CURRENT_PASSWORD", "current password is incorrect")

func (s *UserService) GetProfile(ctx context.Context, userID uuid.UUID) (*dto.ProfileResponse, error) {
	u, err := repository.GetUserByID(ctx, s.pool, userID)
	if err != nil {
		return nil, err
	}
	return dto.NewProfileResponse(u), nil
}

// UpdateProfile changes only name and phone number. Email, status and
// verification state have their own flows. The handler's strict binding
// rejects any request that tries to set them here.
func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, in dto.UpdateProfileRequest) (*dto.ProfileResponse, error) {
	if in.Name == nil && in.PhoneNumber == nil {
		return nil, apperr.BadRequest("NO_CHANGES", "provide at least one of: name, phone_number")
	}
	upd := model.ProfileUpdate{}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, apperr.Field("name", "must not be blank")
		}
		if utf8.RuneCountInString(name) > 100 {
			return nil, apperr.Field("name", "must be at most 100 characters")
		}
		for _, r := range name {
			if unicode.IsControl(r) {
				return nil, apperr.Field("name", "must not contain control characters")
			}
		}
		upd.Name = &name
	}
	if in.PhoneNumber != nil {
		upd.SetPhone = true
		if *in.PhoneNumber != "" {
			if !e164.MatchString(*in.PhoneNumber) {
				return nil, apperr.Field("phone_number", "must be a phone number in E.164 format, e.g. +6281234567890")
			}
			upd.PhoneNumber = in.PhoneNumber
		}
	}
	u, err := repository.UpdateProfile(ctx, s.pool, userID, upd)
	if err != nil {
		return nil, err
	}
	return dto.NewProfileResponse(u), nil
}

// RequestEmailChange sends a code to the new address. Nothing changes until
// the code is confirmed, so a typo or a hijacked session can't silently move
// the account to an address the owner doesn't control.
func (s *UserService) RequestEmailChange(ctx context.Context, userID uuid.UUID, newEmail, password string) (time.Time, error) {
	newEmail = security.NormalizeEmail(newEmail)
	if !security.IsPlainEmail(newEmail) {
		return time.Time{}, apperr.Field("new_email", "must be a valid email address")
	}
	var user *model.User
	var issued *otp.Issued
	err := database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		user, err = repository.LockUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		ok, err := security.VerifyPassword(password, user.PasswordHash)
		if err != nil {
			return err
		}
		if !ok {
			return errWrongPassword
		}
		if strings.EqualFold(user.Email, newEmail) {
			return apperr.Field("new_email", "must be different from the current email")
		}
		taken, err := repository.EmailTaken(ctx, tx, newEmail)
		if err != nil {
			return err
		}
		if taken {
			return apperr.Conflict("EMAIL_ALREADY_REGISTERED", "an account with this email already exists")
		}
		issued, err = s.otp.Issue(ctx, tx, userID, otp.PurposeEmailChange, &newEmail)
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	s.mail.Enqueue(mailer.EmailChangeCode(newEmail, user.Name, issued.Code, s.otp.TTL()))
	return issued.ExpiresAt, nil
}

// ConfirmEmailChange applies the pending change. The unique constraint
// settles a race with someone registering the same address meanwhile: the
// transaction rolls back, the code stays unconsumed, and the caller gets 409.
func (s *UserService) ConfirmEmailChange(ctx context.Context, userID uuid.UUID, code string) (*dto.ProfileResponse, error) {
	var oldEmail string
	var updated *model.User
	err := database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		rec, err := s.otp.Verify(ctx, tx, userID, otp.PurposeEmailChange, code)
		if err != nil {
			return err
		}
		current, err := repository.GetUserByID(ctx, tx, userID)
		if err != nil {
			return err
		}
		oldEmail = current.Email
		updated, err = repository.UpdateEmail(ctx, tx, userID, *rec.TargetEmail)
		if errors.Is(err, repository.ErrEmailTaken) {
			return apperr.Conflict("EMAIL_ALREADY_REGISTERED", "an account with this email already exists")
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	s.mail.Enqueue(mailer.EmailChanged(oldEmail, updated.Name, updated.Email))
	return dto.NewProfileResponse(updated), nil
}

// Deactivate disables the account. In the same transaction it revokes every
// session (so existing access and refresh tokens stop working immediately)
// and retires outstanding codes and reset tokens.
func (s *UserService) Deactivate(ctx context.Context, userID uuid.UUID, password string) error {
	var user *model.User
	err := database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		user, err = repository.LockUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		ok, err := security.VerifyPassword(password, user.PasswordHash)
		if err != nil {
			return err
		}
		if !ok {
			return errWrongPassword
		}
		if err := repository.Deactivate(ctx, tx, userID); err != nil {
			return err
		}
		if err := otp.InvalidateAll(ctx, tx, userID, ""); err != nil {
			return err
		}
		if err := repository.InvalidateResetTokens(ctx, tx, userID); err != nil {
			return err
		}
		_, err = repository.RevokeUserSessions(ctx, tx, userID, model.RevokeAccountDeactivated)
		return err
	})
	if err != nil {
		return err
	}
	s.mail.Enqueue(mailer.AccountDeactivated(user.Email, user.Name))
	return nil
}
