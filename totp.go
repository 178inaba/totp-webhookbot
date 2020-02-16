package totp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/compute/metadata"
	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	"github.com/hgfischer/go-otp"
	"github.com/nlopes/slack"
	"golang.org/x/xerrors"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1"
)

type secretRepository struct {
	client *secretmanager.Client

	projectID string
}

func newSecretRepository(ctx context.Context, projectID string) (*secretRepository, error) {
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, xerrors.Errorf("new secret manager client: %w", err)
	}

	return &secretRepository{client: c, projectID: projectID}, nil
}

func (r *secretRepository) get(ctx context.Context, secretName string) (string, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", r.projectID, secretName),
	}

	resp, err := r.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", xerrors.Errorf("get secret: %w", err)
	}

	return string(resp.Payload.Data), nil
}

func PostTOTP(ctx context.Context, _ struct{}) error {
	projectID, err := metadata.NewClient(&http.Client{}).ProjectID()
	if err != nil {
		return xerrors.Errorf("get project id: %w", err)
	}

	c, err := newSecretRepository(ctx, projectID)
	if err != nil {
		return xerrors.Errorf("new secret repository: %w", err)
	}

	secret, err := c.get(ctx, os.Getenv("TOTP_SECRET_SECRET_ID"))
	if err != nil {
		return xerrors.Errorf("get secret: %w", err)
	}

	webhookRawurl, err := c.get(ctx, os.Getenv("TOTP_SLACK_WEBHOOK_URL_SECRET_ID"))
	if err != nil {
		return xerrors.Errorf("get slack webhook url: %w", err)
	}

	bs, err := hex.DecodeString(secret)
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

	if err := slack.PostWebhook(webhookRawurl, &wm); err != nil {
		return xerrors.Errorf("post webhook: %w", err)
	}

	return nil
}
