// Code generated by protoc-gen-go-hashpb. Do not edit.
// protoc-gen-go-hashpb v0.3.4
// Source: cerbos/cloud/bootstrap/v1/bootstrap.proto

package bootstrapv1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PDPConfig) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bootstrap_v1_PDPConfig_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PDPConfig_Meta) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bootstrap_v1_PDPConfig_Meta_hashpb_sum(m, hasher, ignore)
	}
}
