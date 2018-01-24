package cloudflare

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"
	"time"

	"encoding/base64"
	dcontext "github.com/docker/distribution/context"
	storagedriver "github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/middleware"
	"github.com/docker/distribution/registry/storage/driver/middleware/s3filter"
)

type cloudflareStorageMiddleware struct {
	storagedriver.StorageDriver
	awsIPs     *s3filter.AwsIPs
	baseURL    string
	duration   time.Duration
	signingKey []byte
}

var _ storagedriver.StorageDriver = &cloudflareStorageMiddleware{}

// newCloudflareStorageMiddleware constructs and returns a new Cloudflare
// LayerHandler implementation.
// Required options: baseurl, duration

// Optional options: ipFilteredBy, awsregion
// ipfilteredby: valid value "none|aws|awsregion". "none", do not filter any IP, default value. "aws", only aws IP goes
//               to S3 directly. "awsregion", only regions listed in awsregion options goes to S3 directly
// awsregion: a comma separated string of AWS regions.
// updatefrenquency: how often to update AWS IP list, e.g. 12h
func newCloudflareStorageMiddleware(storageDriver storagedriver.StorageDriver, options map[string]interface{}) (storagedriver.StorageDriver, error) {
	// parse baseurl
	base, ok := options["baseurl"]
	if !ok {
		return nil, fmt.Errorf("no baseurl provided")
	}
	baseURL, ok := base.(string)
	if !ok {
		return nil, fmt.Errorf("baseurl must be a string")
	}
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid baseurl: %v", err)
	}

	// parse duration
	duration := 20 * time.Minute
	if d, ok := options["duration"]; ok {
		switch d := d.(type) {
		case time.Duration:
			duration = d
		case string:
			dur, err := time.ParseDuration(d)
			if err != nil {
				return nil, fmt.Errorf("invalid duration: %s", err)
			}
			duration = dur
		}
	}

	// parse cloudflare signingKey
	key, ok := options["signingkey"]
	if !ok {
		return nil, fmt.Errorf("no singing key is provided for cloudflare middleware")
	}
	signingKey, ok := key.(string)
	if !ok {
		return nil, fmt.Errorf("singing key must be a string")
	}

	awsIPs, err := s3filter.ParseAwsIP(options)
	if err != nil {
		return nil, err
	}

	return &cloudflareStorageMiddleware{
		StorageDriver: storageDriver,
		awsIPs:        awsIPs,
		baseURL:       baseURL,
		duration:      duration,
		signingKey:    []byte(signingKey),
	}, nil
}

// S3BucketKeyer is any type that is capable of returning the S3 bucket key
// which should be cached by cloudflare.
type S3BucketKeyer interface {
	S3BucketKey(path string) string
}

// URLFor attempts to find a url which may be used to retrieve the file at the given path.
// Returns an error if the file cannot be found.
func (lh *cloudflareStorageMiddleware) URLFor(ctx context.Context, path string, options map[string]interface{}) (string, error) {
	keyer, ok := lh.StorageDriver.(S3BucketKeyer)
	if !ok {
		dcontext.GetLogger(ctx).Warn("the cloudflare middleware does not support this backend storage driver")
		return lh.StorageDriver.URLFor(ctx, path, options)
	}

	if s3filter.EligibleForS3(ctx, lh.awsIPs) {
		return lh.StorageDriver.URLFor(ctx, path, options)
	}

	// Get signed cloudflare url
	u, err := generateURL(lh.baseURL, keyer.S3BucketKey(path))
	if err != nil {
		return "", err
	}
	return sign(u, lh.duration, lh.signingKey), nil
}

// init registers the clareflare layerHandler backend.
func init() {
	storagemiddleware.Register("cloudflare", storagemiddleware.InitFunc(newCloudflareStorageMiddleware))
}

func sign(u *url.URL, ttl time.Duration, key []byte) string {
	now := time.Now()
	expiry := now.Add(time.Second * ttl)
	params := url.Values{}
	params.Set("expires", fmt.Sprintf("%d", expiry.Unix()))
	u.RawQuery = params.Encode()
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(u.String()))
	res := mac.Sum(nil)
	fmt.Println(base64.URLEncoding.EncodeToString(res))

	newParams := url.Values{}
	value := fmt.Sprintf("%d-%s", now.Unix(), base64.URLEncoding.EncodeToString(res))
	newParams.Add("verify", value)
	u.RawQuery = newParams.Encode()

	return u.String()
}
func generateURL(base, path string) (*url.URL, error) {
	u, err := url.Parse(base + path)
	if err != nil {
		return nil, err
	}
	return u, nil
}
