// Code generated by protoc-gen-go-hashpb. Do not edit.
// protoc-gen-go-hashpb v0.3.5

package pdpv1

import (
	protowire "google.golang.org/protobuf/encoding/protowire"
	hash "hash"
)

func cerbos_cloud_pdp_v1_Identifier_hashpb_sum(m *Identifier, hasher hash.Hash, ignore map[string]struct{}) {
	if _, ok := ignore["cerbos.cloud.pdp.v1.Identifier.instance"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetInstance()))

	}
	if _, ok := ignore["cerbos.cloud.pdp.v1.Identifier.version"]; !ok {
		_, _ = hasher.Write(protowire.AppendString(nil, m.GetVersion()))

	}
}
