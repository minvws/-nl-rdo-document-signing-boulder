package sa

import (
	"context"
	"time"

	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
)

type rocspWriter interface {
	StoreResponse(ctx context.Context, respBytes []byte, shortIssuerID byte, ttl time.Duration) error
}

// storeOCSPRedis stores an OCSP response in a redis cluster.
func (ssa *SQLStorageAuthority) storeOCSPRedis(ctx context.Context, resp []byte, issuerID int64, ttl time.Duration) error {
	shortIssuerID, err := rocsp_config.FindIssuerByID(issuerID, ssa.shortIssuers)
	if err != nil {
		ssa.redisStoreResponse.WithLabelValues("find_issuer_error").Inc()
		return err
	}
	err = ssa.rocspWriteClient.StoreResponse(ctx, resp, shortIssuerID.ShortID(), ttl)
	if err != nil {
		ssa.redisStoreResponse.WithLabelValues("store_response_error").Inc()
		return err
	}
	ssa.redisStoreResponse.WithLabelValues("success").Inc()
	return nil
}
