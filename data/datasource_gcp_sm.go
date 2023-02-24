package data

import (
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/api/iterator"
	"regexp"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
)

// gcpSecretManagerGetter - A subset of Secret Manager API for use in unit testing
type gcpSecretManagerGetter interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) *secretmanager.SecretIterator
	GetSecretVersion(ctx context.Context, req *secretmanagerpb.GetSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
}

func readGCPSecretManager(ctx context.Context, source *Source, args ...string) ([]byte, error) {
	source.mediaType = jsonMimetype
	if source.gcpSecretManager == nil {
		client, err := secretmanager.NewClient(ctx)
		if err != nil {
			return nil, err
		}
		source.gcpSecretManager = client
	}

	_, paramPath, err := parseDatasourceURLArgs(source.URL, args...)
	if err != nil {
		return nil, err
	}
	paramPath = strings.TrimLeft(paramPath, "/")

	parts := strings.Split(paramPath, "/")
	numParts := len(parts)
	if numParts == 2 {
		var secrets []string
		secretNameRegex := regexp.MustCompile("projects/\\d+/secrets/(.*)")
		req := secretmanagerpb.ListSecretsRequest{
			Parent: paramPath,
		}
		it := source.gcpSecretManager.ListSecrets(ctx, &req)
		for {
			resp, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			// See if it has a value
			getReq := secretmanagerpb.GetSecretVersionRequest{
				Name: fmt.Sprintf("%s/versions/latest", resp.GetName()),
			}

			matches := secretNameRegex.FindStringSubmatch(resp.GetName())
			if len(matches) != 2 {
				return nil, fmt.Errorf("unexpected secret name format: %s", resp.GetName())
			}
			_, err = source.gcpSecretManager.GetSecretVersion(ctx, &getReq)
			if err == nil {
				secrets = append(secrets, matches[1])
			}
		}

		return json.Marshal(secrets)
	} else if numParts == 4 {
		paramPath += "/versions/latest"
	}

	req := secretmanagerpb.AccessSecretVersionRequest{
		Name: paramPath,
	}

	versionData, err := source.gcpSecretManager.AccessSecretVersion(ctx, &req)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf("{\"latest\": \"%s\"}", versionData.Payload.Data)), nil
}
