// Code generated by protoc-gen-go-hashpb. Do not edit.
// protoc-gen-go-hashpb v0.1.0

package bundlev1

import (
	v1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	protowire "google.golang.org/protobuf/encoding/protowire"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	hash "hash"
	sort "sort"
)

func cerbos_cloud_bundle_v1_BundleInfo_Segment_hashpb_sum(m *BundleInfo_Segment, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v1.BundleInfo.Segment.segment_id"]; !ok {
		_, _ = hasher.Write(protowire.AppendVarint(nil, uint64(m.SegmentId)))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.BundleInfo.Segment.checksum"]; !ok {
		_, _ = hasher.Write(protowire.AppendBytes(nil, m.Checksum))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.BundleInfo.Segment.download_urls"]; !ok {
		if len(m.DownloadUrls) > 0 {
			for _, v := range m.DownloadUrls {
				_, _ = hasher.Write(protowire.AppendString(nil, v))

			}
		}
	}
}

func cerbos_cloud_bundle_v1_BundleInfo_hashpb_sum(m *BundleInfo, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v1.BundleInfo.label"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.Label))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.BundleInfo.bundle_hash"]; !ok {
		_, _ = hasher.Write(protowire.AppendBytes(nil, m.BundleHash))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.BundleInfo.segments"]; !ok {
		if len(m.Segments) > 0 {
			for _, v := range m.Segments {
				if v != nil {
					cerbos_cloud_bundle_v1_BundleInfo_Segment_hashpb_sum(v, hasher, ignore)
				}

			}
		}
	}
}

func cerbos_cloud_bundle_v1_GetBundleRequest_hashpb_sum(m *GetBundleRequest, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v1.GetBundleRequest.pdp_id"]; !ok {
		if m.PdpId != nil {
			cerbos_cloud_pdp_v1_Identifier_hashpb_sum(m.PdpId, hasher, ignore)
		}

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.GetBundleRequest.bundle_label"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.BundleLabel))

	}
}

func cerbos_cloud_bundle_v1_GetBundleResponse_hashpb_sum(m *GetBundleResponse, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v1.GetBundleResponse.bundle_info"]; !ok {
		if m.BundleInfo != nil {
			cerbos_cloud_bundle_v1_BundleInfo_hashpb_sum(m.BundleInfo, hasher, ignore)
		}

	}
}

func cerbos_cloud_bundle_v1_Manifest_hashpb_sum(m *Manifest, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v1.Manifest.api_version"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.ApiVersion))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.Manifest.policy_index"]; !ok {
		if len(m.PolicyIndex) > 0 {
			keys := make([]string, len(m.PolicyIndex))
			i := 0
			for k := range m.PolicyIndex {
				keys[i] = k
				i++
			}

			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

			for _, k := range keys {
				_, _ = hasher.Write(protowire.AppendString(nil, m.PolicyIndex[k]))

			}
		}
	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.Manifest.schemas"]; !ok {
		if len(m.Schemas) > 0 {
			for _, v := range m.Schemas {
				_, _ = hasher.Write(protowire.AppendString(nil, v))

			}
		}
	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.Manifest.meta"]; !ok {
		if m.Meta != nil {
			cerbos_cloud_bundle_v1_Meta_hashpb_sum(m.Meta, hasher, ignore)
		}

	}
}

func cerbos_cloud_bundle_v1_Meta_hashpb_sum(m *Meta, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v1.Meta.identifier"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.Identifier))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.Meta.source"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.Source))

	}
}

func cerbos_cloud_bundle_v1_WatchBundleRequest_hashpb_sum(m *WatchBundleRequest, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v1.WatchBundleRequest.pdp_id"]; !ok {
		if m.PdpId != nil {
			cerbos_cloud_pdp_v1_Identifier_hashpb_sum(m.PdpId, hasher, ignore)
		}

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.WatchBundleRequest.bundle_label"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.BundleLabel))

	}
}

func cerbos_cloud_bundle_v1_WatchBundleResponse_BundleRemoved_hashpb_sum(m *WatchBundleResponse_BundleRemoved, hasher hash.Hash, ignore map[string]struct{}) {
}

func cerbos_cloud_bundle_v1_WatchBundleResponse_Reconnect_hashpb_sum(m *WatchBundleResponse_Reconnect, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v1.WatchBundleResponse.Reconnect.backoff"]; !ok {
		if m.Backoff != nil {
			google_protobuf_Duration_hashpb_sum(m.Backoff, hasher, ignore)
		}

	}
	if _, ok := ignore["cerbos.cloud.bundle.v1.WatchBundleResponse.Reconnect.reason"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.Reason))

	}
}

func cerbos_cloud_bundle_v1_WatchBundleResponse_hashpb_sum(m *WatchBundleResponse, hasher hash.Hash, ignore map[string]struct{}) {
	if m.Msg != nil {
		if _, ok := ignore["cerbos.cloud.bundle.v1.WatchBundleResponse.msg"]; !ok {
			switch t := m.Msg.(type) {
			case *WatchBundleResponse_BundleUpdate:
				if t.BundleUpdate != nil {
					cerbos_cloud_bundle_v1_BundleInfo_hashpb_sum(t.BundleUpdate, hasher, ignore)
				}

			case *WatchBundleResponse_Reconnect_:
				if t.Reconnect != nil {
					cerbos_cloud_bundle_v1_WatchBundleResponse_Reconnect_hashpb_sum(t.Reconnect, hasher, ignore)
				}

			case *WatchBundleResponse_BundleRemoved_:
				if t.BundleRemoved != nil {
					cerbos_cloud_bundle_v1_WatchBundleResponse_BundleRemoved_hashpb_sum(t.BundleRemoved, hasher, ignore)
				}

			}
		}
	}
}

func cerbos_cloud_pdp_v1_Identifier_hashpb_sum(m *v1.Identifier, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.pdp.v1.Identifier.instance"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.Instance))

	}
	if _, ok := ignore["cerbos.cloud.pdp.v1.Identifier.version"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.Version))

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
