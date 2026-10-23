// Package handler binds HTTP requests to the auth service.
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"godigi/auth-service/internal/dto"
	"godigi/auth-service/internal/service"
	"godigi/pkg/authn"
	"godigi/pkg/httpx"
)

type AuthHandler struct {
	svc *service.AuthService
}

func New(svc *service.AuthService) *AuthHandler { return &AuthHandler{svc: svc} }

func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	user, err := h.svc.Register(c.Request.Context(), req)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusCreated, "registration successful; a verification code has been sent to your email", user)
}

func (h *AuthHandler) VerifyOTP(c *gin.Context) {
	var req dto.VerifyOTPRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := h.svc.VerifyEmail(c.Request.Context(), req.Email, req.OTP); err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "email verified successfully; you can now log in", nil)
}

func (h *AuthHandler) ResendOTP(c *gin.Context) {
	var req dto.EmailRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := h.svc.ResendVerification(c.Request.Context(), req.Email); err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "if the account exists and is not yet verified, a new code has been sent", nil)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	pair, err := h.svc.Login(c.Request.Context(), req.Email, req.Password, clientInfo(c))
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "login successful", pair)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	pair, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "token refreshed", pair)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := h.svc.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "logged out", nil)
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req dto.EmailRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.svc.RequestPasswordReset(req.Email, httpx.ClientIP(c))
	httpx.OK(c, http.StatusOK, "if an account exists for this email, password reset instructions have been sent", nil)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req dto.ResetPasswordRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "password has been reset; all sessions were signed out, please log in again", nil)
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req dto.ChangePasswordRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	p := authn.From(c)
	if err := h.svc.ChangePassword(c.Request.Context(), p.UserID, p.SessionID, req.CurrentPassword, req.NewPassword); err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "password changed; your other sessions were signed out", nil)
}

func clientInfo(c *gin.Context) dto.ClientInfo {
	return dto.ClientInfo{UserAgent: c.Request.UserAgent(), IP: httpx.ClientIP(c)}
}
