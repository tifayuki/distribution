// Package cloudfront - cloudfront wrapper for storage libs
// N.B. currently only works with S3, not arbitrary sites
//
package cloudfront

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/cloudfront/sign"
	dcontext "github.com/docker/distribution/context"
	storagedriver "github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/middleware"
	"github.com/docker/distribution/registry/storage/driver/middleware/s3filter"
)

// cloudFrontStorageMiddleware provides a simple implementation of layerHandler that
// constructs temporary signed CloudFront URLs from the storagedriver layer URL,
// then issues HTTP Temporary Redirects to this CloudFront content URL.
type cloudFrontStorageMiddleware struct {
	storagedriver.StorageDriver
	awsIPs    *s3filter.AwsIPs
	urlSigner *sign.URLSigner
	baseURL   string
	duration  time.Duration
}

var _ storagedriver.StorageDriver = &cloudFrontStorageMiddleware{}

// newCloudFrontLayerHandler constructs and returns a new CloudFront
// LayerHandler implementation.
// Required options: baseurl, privatekey, keypairid

// Optional options: ipFilteredBy, awsregion
// ipfilteredby: valid value "none|aws|awsregion". "none", do not filter any IP, default value. "aws", only aws IP goes
//               to S3 directly. "awsregion", only regions listed in awsregion options goes to S3 directly
// awsregion: a comma separated string of AWS regions.
// updatefrenquency: how often to update AWS IP list, e.g. 12h
func newCloudFrontStorageMiddleware(storageDriver storagedriver.StorageDriver, options map[string]interface{}) (storagedriver.StorageDriver, error) {
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

	// parse privatekey to get pkPath
	pk, ok := options["privatekey"]
	if !ok {
		return nil, fmt.Errorf("no privatekey provided")
	}
	pkPath, ok := pk.(string)
	if !ok {
		return nil, fmt.Errorf("privatekey must be a string")
	}

	// parse keypairid
	kpid, ok := options["keypairid"]
	if !ok {
		return nil, fmt.Errorf("no keypairid provided")
	}
	keypairID, ok := kpid.(string)
	if !ok {
		return nil, fmt.Errorf("keypairid must be a string")
	}

	// get urlSigner from the file specified in pkPath
	pkBytes, err := ioutil.ReadFile(pkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read privatekey file: %s", err)
	}

	block, _ := pem.Decode([]byte(pkBytes))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key as an rsa private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	urlSigner := sign.NewURLSigner(keypairID, privateKey)

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

	awsIPs, err := s3filter.ParseAwsIP(options)
	if err != nil {
		return nil, err
	}

	return &cloudFrontStorageMiddleware{
		StorageDriver: storageDriver,
		urlSigner:     urlSigner,
		baseURL:       baseURL,
		duration:      duration,
		awsIPs:        awsIPs,
	}, nil
}

// S3BucketKeyer is any type that is capable of returning the S3 bucket key
// which should be cached by AWS CloudFront.
type S3BucketKeyer interface {
	S3BucketKey(path string) string
}

// URLFor attempts to find a url which may be used to retrieve the file at the given path.
// Returns an error if the file cannot be found.
func (lh *cloudFrontStorageMiddleware) URLFor(ctx context.Context, path string, options map[string]interface{}) (string, error) {
	// TODO(endophage): currently only supports S3
	keyer, ok := lh.StorageDriver.(S3BucketKeyer)
	if !ok {
		dcontext.GetLogger(ctx).Warn("the CloudFront middleware does not support this backend storage driver")
		return lh.StorageDriver.URLFor(ctx, path, options)
	}

	if s3filter.EligibleForS3(ctx, lh.awsIPs) {
		return lh.StorageDriver.URLFor(ctx, path, options)
	}

	// Get signed cloudfront url.
	cfURL, err := lh.urlSigner.Sign(lh.baseURL+keyer.S3BucketKey(path), time.Now().Add(lh.duration))
	if err != nil {
		return "", err
	}
	return cfURL, nil
}

// init registers the cloudfront layerHandler backend.
func init() {
	storagemiddleware.Register("cloudfront", storagemiddleware.InitFunc(newCloudFrontStorageMiddleware))
}
