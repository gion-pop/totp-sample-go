package handler

import (
	"bytes"
	"crypto/rand"
	"image/png"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func Handler() http.Handler {
	r := gin.New()

	r.Use(
		gin.Recovery(),
	)

	h := NewTOTPHandler()

	r.POST("/init/:id", h.Init)
	r.POST("/check/:id", h.Check)

	return r
}

type TOTPHandler struct {
	secrets map[string]string
}

func NewTOTPHandler() *TOTPHandler {
	return &TOTPHandler{
		secrets: map[string]string{},
	}
}

func (h *TOTPHandler) Init(c *gin.Context) {
	id := c.Param("id")
	if len(id) == 0 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "totp.example.com",
		AccountName: id,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		Rand:        rand.Reader,
	})
	if err != nil {
		log.Print(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	log.Print(key)
	h.secrets[id] = key.Secret()
	img, err := key.Image(512, 512)
	if err != nil {
		log.Print(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	bs := &bytes.Buffer{}
	if err := png.Encode(bs, img); err != nil {
		log.Print(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, "image/png", bs.Bytes())
	return
}

func (h *TOTPHandler) Check(c *gin.Context) {
	id := c.Param("id")
	if len(id) == 0 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	passcode := c.Query("passcode")

	secret, ok := h.secrets[id]
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if ok := totp.Validate(passcode, secret); !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.Status(http.StatusNoContent)
}
