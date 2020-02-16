package totp

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/hgfischer/go-otp"
	"github.com/nlopes/slack"
	"golang.org/x/xerrors"
)

func PostTOTP(ctx context.Context, _ struct{}) error {
	bs, err := hex.DecodeString("TODO secret")
	if err != nil {
		return xerrors.Errorf("decode secret: %w", err)
	}

	totp := otp.TOTP{
		Secret: string(bs),
		Time:   time.Now(),
		Period: 60,
	}

	wm := slack.WebhookMessage{
		Username:  "TOTP Bot",
		IconEmoji: ":key:",
		Text:      totp.Get(),
	}

	if err := slack.PostWebhook("TODO url", &wm); err != nil {
		return xerrors.Errorf("post webhook: %w", err)
	}

	return nil
}
