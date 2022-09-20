package channels

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"net/url"
	"strings"

	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/common/model"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
)

// GetDecryptedValueFn is a function that returns the decrypted value of
// the given key. If the key is not present, then it returns the fallback value.
type GetDecryptedValueFn func(ctx context.Context, sjd map[string][]byte, key string, fallback string) string

type alertmanagerSettings struct {
	Url      string `json:"url,omitempty" yaml:"url,omitempty"`
	User     string `json:"basicAuthUser,omitempty" yaml:"basicAuthUser,omitempty"`
	Password string `json:"basicAuthPassword,omitempty" yaml:"basicAuthPassword,omitempty"`
}

func AlertmanagerFactory(fc FactoryConfig) (NotificationChannel, error) {
	ch, err := buildAlertmanagerNotifier(fc)
	if err != nil {
		return nil, receiverInitError{
			Reason: err.Error(),
			Cfg:    *fc.Config,
		}
	}
	return ch, nil
}

func buildAlertmanagerNotifier(fc FactoryConfig) (*AlertmanagerNotifier, error) {
	var settings alertmanagerSettings
	err := fc.Config.unmarshalSettings(&settings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	if settings.Url == "" {
		return nil, errors.New("could not find url property in settings")
	}
	var urls []*url.URL
	for _, uS := range strings.Split(settings.Url, ",") {
		uS = strings.TrimSpace(uS)
		if uS == "" {
			continue
		}
		uS = strings.TrimSuffix(uS, "/") + "/api/v1/alerts"
		url, err := url.Parse(uS)
		if err != nil {
			return nil, fmt.Errorf("invalid url property in settings: %w", err)
		}
		urls = append(urls, url)
	}
	settings.Password = fc.DecryptFunc(context.Background(), fc.Config.SecureSettings, "basicAuthPassword", settings.Password)

	return &AlertmanagerNotifier{
		Base: NewBase(&models.AlertNotification{
			Uid:                   fc.Config.UID,
			Name:                  fc.Config.Name,
			Type:                  fc.Config.Type,
			DisableResolveMessage: fc.Config.DisableResolveMessage,
			Settings:              fc.Config.Settings,
		}),

		images:   fc.ImageStore,
		urls:     urls,
		settings: settings,
		logger:   log.New("alerting.notifier.prometheus-alertmanager"),
	}, nil
}

// AlertmanagerNotifier sends alert notifications to the alert manager
type AlertmanagerNotifier struct {
	*Base
	images ImageStore

	urls     []*url.URL
	settings alertmanagerSettings
	logger   log.Logger
}

// Notify sends alert notifications to Alertmanager.
func (n *AlertmanagerNotifier) Notify(ctx context.Context, as ...*types.Alert) (bool, error) {
	n.logger.Debug("sending Alertmanager alert", "alertmanager", n.Name)
	if len(as) == 0 {
		return true, nil
	}

	_ = withStoredImages(ctx, n.logger, n.images,
		func(index int, image ngmodels.Image) error {
			// If there is an image for this alert and the image has been uploaded
			// to a public URL then include it as an annotation
			if image.URL != "" {
				as[index].Annotations["image"] = model.LabelValue(image.URL)
			}
			return nil
		}, as...)

	body, err := json.Marshal(as)
	if err != nil {
		return false, err
	}

	var (
		lastErr error
		numErrs int
	)
	for _, u := range n.urls {
		if _, err := sendHTTPRequest(ctx, u, httpCfg{
			user:     n.settings.User,
			password: n.settings.Password,
			body:     body,
		}, n.logger); err != nil {
			n.logger.Warn("failed to send to Alertmanager", "err", err, "alertmanager", n.Name, "url", u.String())
			lastErr = err
			numErrs++
		}
	}

	if numErrs == len(n.urls) {
		// All attempts to send alerts have failed
		n.logger.Warn("all attempts to send to Alertmanager failed", "alertmanager", n.Name)
		return false, fmt.Errorf("failed to send alert to Alertmanager: %w", lastErr)
	}

	return true, nil
}

func (n *AlertmanagerNotifier) SendResolved() bool {
	return !n.GetDisableResolveMessage()
}
