package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"godigi/core-service/internal/dto"
	"godigi/core-service/internal/service"
	"godigi/pkg/authn"
	"godigi/pkg/httpx"
)

type UserHandler struct {
	svc *service.UserService
}

func New(svc *service.UserService) *UserHandler { return &UserHandler{svc: svc} }

func (h *UserHandler) GetMe(c *gin.Context) {
	p, err := h.svc.GetProfile(c.Request.Context(), authn.From(c).UserID)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "", p)
}

func (h *UserHandler) UpdateMe(c *gin.Context) {
	var req dto.UpdateProfileRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	p, err := h.svc.UpdateProfile(c.Request.Context(), authn.From(c).UserID, req)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "profile updated", p)
}

func (h *UserHandler) ChangeEmail(c *gin.Context) {
	var req dto.ChangeEmailRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	expires, err := h.svc.RequestEmailChange(c.Request.Context(), authn.From(c).UserID, req.NewEmail, req.CurrentPassword)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusAccepted, "a verification code has been sent to the new email address",
		dto.NewEmailChangeResponse(expires))
}

func (h *UserHandler) VerifyEmailChange(c *gin.Context) {
	var req dto.VerifyEmailChangeRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	p, err := h.svc.ConfirmEmailChange(c.Request.Context(), authn.From(c).UserID, req.OTP)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "email address updated", p)
}

func (h *UserHandler) Deactivate(c *gin.Context) {
	var req dto.DeactivateRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := h.svc.Deactivate(c.Request.Context(), authn.From(c).UserID, req.CurrentPassword); err != nil {
		httpx.Fail(c, err)
		return
	}
	httpx.OK(c, http.StatusOK, "account deactivated; all sessions have been signed out", nil)
}
