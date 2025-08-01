// Code generated by protoc-gen-go-hashpb. DO NOT EDIT.
// protoc-gen-go-hashpb v0.4.2
// Source: cerbos/cloud/bundle/v1/bundle.proto

package bundlev1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *BundleInfo) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_BundleInfo_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *BundleInfo_Segment) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_BundleInfo_Segment_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Meta) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_Meta_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Manifest) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_Manifest_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *GetBundleRequest) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_GetBundleRequest_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *GetBundleResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_GetBundleResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *WatchBundleRequest) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_WatchBundleRequest_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *WatchBundleRequest_WatchLabel) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_WatchBundleRequest_WatchLabel_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *WatchBundleRequest_Heartbeat) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_WatchBundleRequest_Heartbeat_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *WatchBundleResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_WatchBundleResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *WatchBundleResponse_Reconnect) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_cloud_bundle_v1_WatchBundleResponse_Reconnect_hashpb_sum(m, hasher, ignore)
	}
}
