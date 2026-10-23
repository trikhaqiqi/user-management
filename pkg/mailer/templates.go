package mailer

import (
	"fmt"
	"time"
)

func minutes(d time.Duration) int { return int(d.Round(time.Minute) / time.Minute) }

func VerificationCode(to, name, code string, ttl time.Duration) Message {
	return Message{
		To:      to,
		Subject: "Your Godigi verification code",
		Body: fmt.Sprintf("Hi %s,\n\nYour verification code is: %s\n\n"+
			"It expires in %d minutes and can be used once. If you did not create an account, ignore this email.\n",
			name, code, minutes(ttl)),
	}
}

func EmailChangeCode(to, name, code string, ttl time.Duration) Message {
	return Message{
		To:      to,
		Subject: "Confirm your new Godigi email address",
		Body: fmt.Sprintf("Hi %s,\n\nUse this code to confirm %s as your new email address: %s\n\n"+
			"It expires in %d minutes. If you did not request this change, ignore this email.\n",
			name, to, code, minutes(ttl)),
	}
}

func PasswordReset(to, name, token, resetURL string, ttl time.Duration) Message {
	return Message{
		To:      to,
		Subject: "Reset your Godigi password",
		Body: fmt.Sprintf("Hi %s,\n\nWe received a request to reset your password.\n\n"+
			"Reset link: %s?token=%s\n\nOr use this reset token with POST /api/v1/auth/reset-password:\n%s\n\n"+
			"The token expires in %d minutes and can be used once. If you did not ask for this, ignore this email; "+
			"your password has not changed.\n",
			name, resetURL, token, token, minutes(ttl)),
	}
}

func PasswordChanged(to, name string) Message {
	return Message{
		To:      to,
		Subject: "Your Godigi password was changed",
		Body: fmt.Sprintf("Hi %s,\n\nThe password for your account was just changed and other sessions were signed out.\n"+
			"If this was not you, reset your password immediately.\n", name),
	}
}

func EmailChanged(to, name, newEmail string) Message {
	return Message{
		To:      to,
		Subject: "Your Godigi email address was changed",
		Body: fmt.Sprintf("Hi %s,\n\nThe email address on your account was changed to %s.\n"+
			"If this was not you, contact support immediately.\n", name, newEmail),
	}
}

func AccountDeactivated(to, name string) Message {
	return Message{
		To:      to,
		Subject: "Your Godigi account was deactivated",
		Body:    fmt.Sprintf("Hi %s,\n\nYour account has been deactivated and all sessions were signed out.\n", name),
	}
}
