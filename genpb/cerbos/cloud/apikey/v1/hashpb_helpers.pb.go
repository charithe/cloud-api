// Code generated by protoc-gen-go-hashpb. Do not edit.
// protoc-gen-go-hashpb v0.1.0

package apikeyv1

import (
	protowire "google.golang.org/protobuf/encoding/protowire"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	hash "hash"
)

func cerbos_cloud_apikey_v1_IssueAccessTokenRequest_hashpb_sum(m *IssueAccessTokenRequest, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.apikey.v1.IssueAccessTokenRequest.client_id"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.ClientId))

	}
	if _, ok := ignore["cerbos.cloud.apikey.v1.IssueAccessTokenRequest.client_secret"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.ClientSecret))

	}
}

func cerbos_cloud_apikey_v1_IssueAccessTokenResponse_hashpb_sum(m *IssueAccessTokenResponse, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.apikey.v1.IssueAccessTokenResponse.access_token"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.AccessToken))

	}
	if _, ok := ignore["cerbos.cloud.apikey.v1.IssueAccessTokenResponse.expires_in"]; !ok {
		if m.ExpiresIn != nil {
			google_protobuf_Duration_hashpb_sum(m.ExpiresIn, hasher, ignore)
		}

	}
}

func google_protobuf_Duration_hashpb_sum(m *durationpb.Duration, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["google.protobuf.Duration.seconds"]; !ok {
		_, _ = hasher.Write(protowire.AppendVarint(nil, uint64(m.Seconds)))

	}
	if _, ok := ignore["google.protobuf.Duration.nanos"]; !ok {
		_, _ = hasher.Write(protowire.AppendVarint(nil, uint64(m.Nanos)))

	}
}