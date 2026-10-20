// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package logcap

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/cerbos/cloud-api/base"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1/logsv1connect"
)

var ingestRPCSpec = sync.OnceValue(func() connect.Spec {
	return connect.Spec{
		StreamType: connect.StreamTypeUnary,
		Schema:     logsv1.File_cerbos_cloud_logs_v1_logs_proto.Services().ByName("CerbosLogsService").Methods().ByName("Ingest"),
		Procedure:  logsv1connect.CerbosLogsServiceIngestProcedure,
	}
})

type Client struct {
	rpcClient    logsv1connect.CerbosLogsServiceClient
	rawRPCClient *connect.Client
	base.Client
}

func NewClient(baseClient base.Client, options []connecthttp.Option, interceptors []connect.ClientInterceptor) (*Client, error) {
	httpClient := baseClient.StdHTTPClient() // Bidi streams don't work with retryable HTTP client.
	rpcClient := logsv1connect.NewCerbosLogsServiceClient(connect.NewClient(connecthttp.NewTransport(httpClient, baseClient.APIEndpoint, options...), interceptors...))

	rawRPCClient := connect.NewClient(connecthttp.NewTransport(httpClient, baseClient.APIEndpoint, options...), interceptors...)

	return &Client{
		Client:       baseClient,
		rpcClient:    rpcClient,
		rawRPCClient: rawRPCClient,
	}, nil
}

type Target interface {
	ToProto() *logsv1.IngestTarget
}

type WorkspaceID string

var _ Target = WorkspaceID("")

func (id WorkspaceID) ToProto() *logsv1.IngestTarget {
	return &logsv1.IngestTarget{
		Target: &logsv1.IngestTarget_WorkspaceId{
			WorkspaceId: string(id),
		},
	}
}

type DeploymentID string

var _ Target = DeploymentID("")

func (id DeploymentID) ToProto() *logsv1.IngestTarget {
	return &logsv1.IngestTarget{
		Target: &logsv1.IngestTarget_DeploymentId{
			DeploymentId: string(id),
		},
	}
}

func (c *Client) Ingest(ctx context.Context, target Target, batch *logsv1.IngestBatch) (time.Duration, error) {
	log := c.Logger
	log.V(1).Info("Calling Ingest RPC")

	req := &logsv1.IngestRequest{
		PdpId: c.PDPIdentifier,
		Batch: batch,
	}

	if target != nil {
		req.Target = target.ToProto()
	}

	resp, err := c.rpcClient.Ingest(ctx, req)
	if err != nil {
		log.Error(err, "Ingest RPC failed")
		return 0, err
	}

	base.LogResponsePayload(log, resp)

	return resp.GetBackoff().GetDuration().AsDuration(), nil
}

// IngestRaw is Ingest for callers that already hold the batch in serialized
// form. batch must be a serialized logsv1.IngestBatch.
func (c *Client) IngestRaw(ctx context.Context, target Target, batch []byte) (time.Duration, error) {
	log := c.Logger
	log.V(1).Info("Calling Ingest RPC (raw)")

	req := &logsv1.RawIngestRequest{
		PdpId: c.PDPIdentifier,
		Batch: batch,
	}

	if target != nil {
		req.Target = target.ToProto()
	}

	var resp logsv1.IngestResponse
	err := c.rawRPCClient.CallUnary(ctx, ingestRPCSpec(), req, &resp)
	if err != nil {
		log.Error(err, "Ingest RPC failed")
		return 0, err
	}

	base.LogResponsePayload(log, &resp)

	return resp.GetBackoff().GetDuration().AsDuration(), nil
}
