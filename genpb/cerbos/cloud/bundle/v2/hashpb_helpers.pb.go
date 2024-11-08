// Code generated by protoc-gen-go-hashpb. Do not edit.
// protoc-gen-go-hashpb v0.3.1

package bundlev2

import (
	v1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	protowire "google.golang.org/protobuf/encoding/protowire"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	hash "hash"
	sort "sort"
)

func cerbos_cloud_bundle_v2_BundleInfo_Segment_hashpb_sum(m *BundleInfo_Segment, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.BundleInfo.Segment.segment_id"]; !ok {
		_, _ = hasher.Write(protowire.AppendVarint(nil, uint64(m.GetSegmentId())))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.BundleInfo.Segment.checksum"]; !ok {
		_, _ = hasher.Write(protowire.AppendBytes(nil, m.GetChecksum()))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.BundleInfo.Segment.download_urls"]; !ok {
		if len(m.DownloadUrls) > 0 {
			for _, v := range m.DownloadUrls {
				_, _ = hasher.Write(protowire.AppendString(nil, v))

			}
		}
	}
}

func cerbos_cloud_bundle_v2_BundleInfo_hashpb_sum(m *BundleInfo, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.BundleInfo.label"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetLabel()))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.BundleInfo.input_hash"]; !ok {
		_, _ = hasher.Write(protowire.AppendBytes(nil, m.GetInputHash()))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.BundleInfo.output_hash"]; !ok {
		_, _ = hasher.Write(protowire.AppendBytes(nil, m.GetOutputHash()))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.BundleInfo.encryption_key"]; !ok {
		_, _ = hasher.Write(protowire.AppendBytes(nil, m.GetEncryptionKey()))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.BundleInfo.segments"]; !ok {
		if len(m.Segments) > 0 {
			for _, v := range m.Segments {
				if v != nil {
					cerbos_cloud_bundle_v2_BundleInfo_Segment_hashpb_sum(v, hasher, ignore)
				}

			}
		}
	}
}

func cerbos_cloud_bundle_v2_GetBundleRequest_hashpb_sum(m *GetBundleRequest, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.GetBundleRequest.pdp_id"]; !ok {
		if m.GetPdpId() != nil {
			cerbos_cloud_pdp_v1_Identifier_hashpb_sum(m.GetPdpId(), hasher, ignore)
		}

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.GetBundleRequest.bundle_label"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetBundleLabel()))

	}
}

func cerbos_cloud_bundle_v2_GetBundleResponse_hashpb_sum(m *GetBundleResponse, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.GetBundleResponse.bundle_info"]; !ok {
		if m.GetBundleInfo() != nil {
			cerbos_cloud_bundle_v2_BundleInfo_hashpb_sum(m.GetBundleInfo(), hasher, ignore)
		}

	}
}

func cerbos_cloud_bundle_v2_Manifest_hashpb_sum(m *Manifest, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.Manifest.api_version"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetApiVersion()))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.Manifest.policy_index"]; !ok {
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
	if _, ok := ignore["cerbos.cloud.bundle.v2.Manifest.schemas"]; !ok {
		if len(m.Schemas) > 0 {
			for _, v := range m.Schemas {
				_, _ = hasher.Write(protowire.AppendString(nil, v))

			}
		}
	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.Manifest.meta"]; !ok {
		if m.GetMeta() != nil {
			cerbos_cloud_bundle_v2_Meta_hashpb_sum(m.GetMeta(), hasher, ignore)
		}

	}
}

func cerbos_cloud_bundle_v2_Meta_hashpb_sum(m *Meta, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.Meta.identifier"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetIdentifier()))

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.Meta.source"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetSource()))

	}
}

func cerbos_cloud_bundle_v2_WatchBundleRequest_Heartbeat_hashpb_sum(m *WatchBundleRequest_Heartbeat, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.WatchBundleRequest.Heartbeat.timestamp"]; !ok {
		if m.GetTimestamp() != nil {
			google_protobuf_Timestamp_hashpb_sum(m.GetTimestamp(), hasher, ignore)
		}

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.WatchBundleRequest.Heartbeat.active_bundle_id"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetActiveBundleId()))

	}
}

func cerbos_cloud_bundle_v2_WatchBundleRequest_WatchLabel_hashpb_sum(m *WatchBundleRequest_WatchLabel, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.WatchBundleRequest.WatchLabel.bundle_label"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetBundleLabel()))

	}
}

func cerbos_cloud_bundle_v2_WatchBundleRequest_hashpb_sum(m *WatchBundleRequest, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.WatchBundleRequest.pdp_id"]; !ok {
		if m.GetPdpId() != nil {
			cerbos_cloud_pdp_v1_Identifier_hashpb_sum(m.GetPdpId(), hasher, ignore)
		}

	}
	if m.Msg != nil {
		if _, ok := ignore["cerbos.cloud.bundle.v2.WatchBundleRequest.msg"]; !ok {
			switch t := m.Msg.(type) {
			case *WatchBundleRequest_WatchLabel_:
				if t.WatchLabel != nil {
					cerbos_cloud_bundle_v2_WatchBundleRequest_WatchLabel_hashpb_sum(t.WatchLabel, hasher, ignore)
				}

			case *WatchBundleRequest_Heartbeat_:
				if t.Heartbeat != nil {
					cerbos_cloud_bundle_v2_WatchBundleRequest_Heartbeat_hashpb_sum(t.Heartbeat, hasher, ignore)
				}

			}
		}
	}
}

func cerbos_cloud_bundle_v2_WatchBundleResponse_BundleRemoved_hashpb_sum(m *WatchBundleResponse_BundleRemoved, hasher hash.Hash, ignore map[string]struct{}) {
}

func cerbos_cloud_bundle_v2_WatchBundleResponse_Reconnect_hashpb_sum(m *WatchBundleResponse_Reconnect, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.bundle.v2.WatchBundleResponse.Reconnect.backoff"]; !ok {
		if m.GetBackoff() != nil {
			google_protobuf_Duration_hashpb_sum(m.GetBackoff(), hasher, ignore)
		}

	}
	if _, ok := ignore["cerbos.cloud.bundle.v2.WatchBundleResponse.Reconnect.reason"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetReason()))

	}
}

func cerbos_cloud_bundle_v2_WatchBundleResponse_hashpb_sum(m *WatchBundleResponse, hasher hash.Hash, ignore map[string]struct{}) {
	if m.Msg != nil {
		if _, ok := ignore["cerbos.cloud.bundle.v2.WatchBundleResponse.msg"]; !ok {
			switch t := m.Msg.(type) {
			case *WatchBundleResponse_BundleUpdate:
				if t.BundleUpdate != nil {
					cerbos_cloud_bundle_v2_BundleInfo_hashpb_sum(t.BundleUpdate, hasher, ignore)
				}

			case *WatchBundleResponse_Reconnect_:
				if t.Reconnect != nil {
					cerbos_cloud_bundle_v2_WatchBundleResponse_Reconnect_hashpb_sum(t.Reconnect, hasher, ignore)
				}

			case *WatchBundleResponse_BundleRemoved_:
				if t.BundleRemoved != nil {
					cerbos_cloud_bundle_v2_WatchBundleResponse_BundleRemoved_hashpb_sum(t.BundleRemoved, hasher, ignore)
				}

			}
		}
	}
}

func cerbos_cloud_pdp_v1_Identifier_hashpb_sum(m *v1.Identifier, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.pdp.v1.Identifier.instance"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetInstance()))

	}
	if _, ok := ignore["cerbos.cloud.pdp.v1.Identifier.version"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetVersion()))

	}
}

func google_protobuf_Duration_hashpb_sum(m *durationpb.Duration, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["google.protobuf.Duration.seconds"]; !ok {
		_, _ = hasher.Write(protowire.AppendVarint(nil, uint64(m.GetSeconds())))

	}
	if _, ok := ignore["google.protobuf.Duration.nanos"]; !ok {
		_, _ = hasher.Write(protowire.AppendVarint(nil, uint64(m.GetNanos())))

	}
}

func google_protobuf_Timestamp_hashpb_sum(m *timestamppb.Timestamp, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["google.protobuf.Timestamp.seconds"]; !ok {
		_, _ = hasher.Write(protowire.AppendVarint(nil, uint64(m.GetSeconds())))

	}
	if _, ok := ignore["google.protobuf.Timestamp.nanos"]; !ok {
		_, _ = hasher.Write(protowire.AppendVarint(nil, uint64(m.GetNanos())))

	}
}
