// Code generated by protoc-gen-go-hashpb. Do not edit.
// protoc-gen-go-hashpb v0.3.1
// Source: cerbos/cloud/apikey/v1/apikey.proto

package apikeyv1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *IssueAccessTokenRequest) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_apikey_v1_IssueAccessTokenRequest_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *IssueAccessTokenResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_apikey_v1_IssueAccessTokenResponse_hashpb_sum(m, hasher, ignore)
	}
}
