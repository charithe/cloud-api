// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: cerbos/cloud/bundle/v2/bundle.proto

package bundlev2

import (
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	v1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	_ "google.golang.org/genproto/googleapis/api/visibility"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Source struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Source:
	//
	//	*Source_DeploymentId
	//	*Source_PlaygroundId
	Source        isSource_Source `protobuf_oneof:"source"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Source) Reset() {
	*x = Source{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Source) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Source) ProtoMessage() {}

func (x *Source) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Source.ProtoReflect.Descriptor instead.
func (*Source) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{0}
}

func (x *Source) GetSource() isSource_Source {
	if x != nil {
		return x.Source
	}
	return nil
}

func (x *Source) GetDeploymentId() string {
	if x != nil {
		if x, ok := x.Source.(*Source_DeploymentId); ok {
			return x.DeploymentId
		}
	}
	return ""
}

func (x *Source) GetPlaygroundId() string {
	if x != nil {
		if x, ok := x.Source.(*Source_PlaygroundId); ok {
			return x.PlaygroundId
		}
	}
	return ""
}

type isSource_Source interface {
	isSource_Source()
}

type Source_DeploymentId struct {
	DeploymentId string `protobuf:"bytes,1,opt,name=deployment_id,json=deploymentId,proto3,oneof"`
}

type Source_PlaygroundId struct {
	PlaygroundId string `protobuf:"bytes,2,opt,name=playground_id,json=playgroundId,proto3,oneof"`
}

func (*Source_DeploymentId) isSource_Source() {}

func (*Source_PlaygroundId) isSource_Source() {}

// BundleInfo holds information about a bundle and its download URLs.
type BundleInfo struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Source        *Source                `protobuf:"bytes,1,opt,name=source,proto3" json:"source,omitempty"`
	InputHash     []byte                 `protobuf:"bytes,2,opt,name=input_hash,json=inputHash,proto3" json:"input_hash,omitempty"`
	OutputHash    []byte                 `protobuf:"bytes,3,opt,name=output_hash,json=outputHash,proto3" json:"output_hash,omitempty"`
	EncryptionKey []byte                 `protobuf:"bytes,4,opt,name=encryption_key,json=encryptionKey,proto3" json:"encryption_key,omitempty"`
	Segments      []*BundleInfo_Segment  `protobuf:"bytes,5,rep,name=segments,proto3" json:"segments,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BundleInfo) Reset() {
	*x = BundleInfo{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BundleInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BundleInfo) ProtoMessage() {}

func (x *BundleInfo) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BundleInfo.ProtoReflect.Descriptor instead.
func (*BundleInfo) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{1}
}

func (x *BundleInfo) GetSource() *Source {
	if x != nil {
		return x.Source
	}
	return nil
}

func (x *BundleInfo) GetInputHash() []byte {
	if x != nil {
		return x.InputHash
	}
	return nil
}

func (x *BundleInfo) GetOutputHash() []byte {
	if x != nil {
		return x.OutputHash
	}
	return nil
}

func (x *BundleInfo) GetEncryptionKey() []byte {
	if x != nil {
		return x.EncryptionKey
	}
	return nil
}

func (x *BundleInfo) GetSegments() []*BundleInfo_Segment {
	if x != nil {
		return x.Segments
	}
	return nil
}

type Meta struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	BundleId      string                 `protobuf:"bytes,1,opt,name=bundle_id,json=bundleId,proto3" json:"bundle_id,omitempty"`
	Source        string                 `protobuf:"bytes,2,opt,name=source,proto3" json:"source,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Meta) Reset() {
	*x = Meta{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Meta) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Meta) ProtoMessage() {}

func (x *Meta) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Meta.ProtoReflect.Descriptor instead.
func (*Meta) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{2}
}

func (x *Meta) GetBundleId() string {
	if x != nil {
		return x.BundleId
	}
	return ""
}

func (x *Meta) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

type Manifest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ApiVersion    string                 `protobuf:"bytes,1,opt,name=api_version,json=apiVersion,proto3" json:"api_version,omitempty"`
	PolicyIndex   map[string]string      `protobuf:"bytes,2,rep,name=policy_index,json=policyIndex,proto3" json:"policy_index,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Schemas       []string               `protobuf:"bytes,3,rep,name=schemas,proto3" json:"schemas,omitempty"`
	Meta          *Meta                  `protobuf:"bytes,4,opt,name=meta,proto3" json:"meta,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Manifest) Reset() {
	*x = Manifest{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Manifest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Manifest) ProtoMessage() {}

func (x *Manifest) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Manifest.ProtoReflect.Descriptor instead.
func (*Manifest) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{3}
}

func (x *Manifest) GetApiVersion() string {
	if x != nil {
		return x.ApiVersion
	}
	return ""
}

func (x *Manifest) GetPolicyIndex() map[string]string {
	if x != nil {
		return x.PolicyIndex
	}
	return nil
}

func (x *Manifest) GetSchemas() []string {
	if x != nil {
		return x.Schemas
	}
	return nil
}

func (x *Manifest) GetMeta() *Meta {
	if x != nil {
		return x.Meta
	}
	return nil
}

type GetBundleRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PdpId         *v1.Identifier         `protobuf:"bytes,1,opt,name=pdp_id,json=pdpId,proto3" json:"pdp_id,omitempty"`
	Source        *Source                `protobuf:"bytes,2,opt,name=source,proto3" json:"source,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetBundleRequest) Reset() {
	*x = GetBundleRequest{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetBundleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetBundleRequest) ProtoMessage() {}

func (x *GetBundleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetBundleRequest.ProtoReflect.Descriptor instead.
func (*GetBundleRequest) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{4}
}

func (x *GetBundleRequest) GetPdpId() *v1.Identifier {
	if x != nil {
		return x.PdpId
	}
	return nil
}

func (x *GetBundleRequest) GetSource() *Source {
	if x != nil {
		return x.Source
	}
	return nil
}

type GetBundleResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	BundleInfo    *BundleInfo            `protobuf:"bytes,1,opt,name=bundle_info,json=bundleInfo,proto3" json:"bundle_info,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetBundleResponse) Reset() {
	*x = GetBundleResponse{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetBundleResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetBundleResponse) ProtoMessage() {}

func (x *GetBundleResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetBundleResponse.ProtoReflect.Descriptor instead.
func (*GetBundleResponse) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{5}
}

func (x *GetBundleResponse) GetBundleInfo() *BundleInfo {
	if x != nil {
		return x.BundleInfo
	}
	return nil
}

type WatchBundleRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	PdpId *v1.Identifier         `protobuf:"bytes,1,opt,name=pdp_id,json=pdpId,proto3" json:"pdp_id,omitempty"`
	// Types that are valid to be assigned to Msg:
	//
	//	*WatchBundleRequest_Start_
	//	*WatchBundleRequest_Heartbeat_
	Msg           isWatchBundleRequest_Msg `protobuf_oneof:"msg"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *WatchBundleRequest) Reset() {
	*x = WatchBundleRequest{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WatchBundleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WatchBundleRequest) ProtoMessage() {}

func (x *WatchBundleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WatchBundleRequest.ProtoReflect.Descriptor instead.
func (*WatchBundleRequest) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{6}
}

func (x *WatchBundleRequest) GetPdpId() *v1.Identifier {
	if x != nil {
		return x.PdpId
	}
	return nil
}

func (x *WatchBundleRequest) GetMsg() isWatchBundleRequest_Msg {
	if x != nil {
		return x.Msg
	}
	return nil
}

func (x *WatchBundleRequest) GetStart() *WatchBundleRequest_Start {
	if x != nil {
		if x, ok := x.Msg.(*WatchBundleRequest_Start_); ok {
			return x.Start
		}
	}
	return nil
}

func (x *WatchBundleRequest) GetHeartbeat() *WatchBundleRequest_Heartbeat {
	if x != nil {
		if x, ok := x.Msg.(*WatchBundleRequest_Heartbeat_); ok {
			return x.Heartbeat
		}
	}
	return nil
}

type isWatchBundleRequest_Msg interface {
	isWatchBundleRequest_Msg()
}

type WatchBundleRequest_Start_ struct {
	Start *WatchBundleRequest_Start `protobuf:"bytes,2,opt,name=start,proto3,oneof"`
}

type WatchBundleRequest_Heartbeat_ struct {
	Heartbeat *WatchBundleRequest_Heartbeat `protobuf:"bytes,3,opt,name=heartbeat,proto3,oneof"`
}

func (*WatchBundleRequest_Start_) isWatchBundleRequest_Msg() {}

func (*WatchBundleRequest_Heartbeat_) isWatchBundleRequest_Msg() {}

type WatchBundleResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Msg:
	//
	//	*WatchBundleResponse_BundleUpdate
	//	*WatchBundleResponse_Reconnect_
	//	*WatchBundleResponse_BundleRemoved_
	Msg           isWatchBundleResponse_Msg `protobuf_oneof:"msg"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *WatchBundleResponse) Reset() {
	*x = WatchBundleResponse{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WatchBundleResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WatchBundleResponse) ProtoMessage() {}

func (x *WatchBundleResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WatchBundleResponse.ProtoReflect.Descriptor instead.
func (*WatchBundleResponse) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{7}
}

func (x *WatchBundleResponse) GetMsg() isWatchBundleResponse_Msg {
	if x != nil {
		return x.Msg
	}
	return nil
}

func (x *WatchBundleResponse) GetBundleUpdate() *BundleInfo {
	if x != nil {
		if x, ok := x.Msg.(*WatchBundleResponse_BundleUpdate); ok {
			return x.BundleUpdate
		}
	}
	return nil
}

func (x *WatchBundleResponse) GetReconnect() *WatchBundleResponse_Reconnect {
	if x != nil {
		if x, ok := x.Msg.(*WatchBundleResponse_Reconnect_); ok {
			return x.Reconnect
		}
	}
	return nil
}

func (x *WatchBundleResponse) GetBundleRemoved() *WatchBundleResponse_BundleRemoved {
	if x != nil {
		if x, ok := x.Msg.(*WatchBundleResponse_BundleRemoved_); ok {
			return x.BundleRemoved
		}
	}
	return nil
}

type isWatchBundleResponse_Msg interface {
	isWatchBundleResponse_Msg()
}

type WatchBundleResponse_BundleUpdate struct {
	BundleUpdate *BundleInfo `protobuf:"bytes,1,opt,name=bundle_update,json=bundleUpdate,proto3,oneof"`
}

type WatchBundleResponse_Reconnect_ struct {
	Reconnect *WatchBundleResponse_Reconnect `protobuf:"bytes,2,opt,name=reconnect,proto3,oneof"`
}

type WatchBundleResponse_BundleRemoved_ struct {
	BundleRemoved *WatchBundleResponse_BundleRemoved `protobuf:"bytes,3,opt,name=bundle_removed,json=bundleRemoved,proto3,oneof"`
}

func (*WatchBundleResponse_BundleUpdate) isWatchBundleResponse_Msg() {}

func (*WatchBundleResponse_Reconnect_) isWatchBundleResponse_Msg() {}

func (*WatchBundleResponse_BundleRemoved_) isWatchBundleResponse_Msg() {}

type BundleInfo_Segment struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	SegmentId     uint32                 `protobuf:"varint,1,opt,name=segment_id,json=segmentId,proto3" json:"segment_id,omitempty"`
	Checksum      []byte                 `protobuf:"bytes,2,opt,name=checksum,proto3" json:"checksum,omitempty"`
	DownloadUrls  []string               `protobuf:"bytes,3,rep,name=download_urls,json=downloadUrls,proto3" json:"download_urls,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BundleInfo_Segment) Reset() {
	*x = BundleInfo_Segment{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BundleInfo_Segment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BundleInfo_Segment) ProtoMessage() {}

func (x *BundleInfo_Segment) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BundleInfo_Segment.ProtoReflect.Descriptor instead.
func (*BundleInfo_Segment) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{1, 0}
}

func (x *BundleInfo_Segment) GetSegmentId() uint32 {
	if x != nil {
		return x.SegmentId
	}
	return 0
}

func (x *BundleInfo_Segment) GetChecksum() []byte {
	if x != nil {
		return x.Checksum
	}
	return nil
}

func (x *BundleInfo_Segment) GetDownloadUrls() []string {
	if x != nil {
		return x.DownloadUrls
	}
	return nil
}

type WatchBundleRequest_Start struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Source        *Source                `protobuf:"bytes,1,opt,name=source,proto3" json:"source,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *WatchBundleRequest_Start) Reset() {
	*x = WatchBundleRequest_Start{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WatchBundleRequest_Start) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WatchBundleRequest_Start) ProtoMessage() {}

func (x *WatchBundleRequest_Start) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WatchBundleRequest_Start.ProtoReflect.Descriptor instead.
func (*WatchBundleRequest_Start) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{6, 0}
}

func (x *WatchBundleRequest_Start) GetSource() *Source {
	if x != nil {
		return x.Source
	}
	return nil
}

type WatchBundleRequest_Heartbeat struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Timestamp      *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	ActiveBundleId string                 `protobuf:"bytes,2,opt,name=active_bundle_id,json=activeBundleId,proto3" json:"active_bundle_id,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *WatchBundleRequest_Heartbeat) Reset() {
	*x = WatchBundleRequest_Heartbeat{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WatchBundleRequest_Heartbeat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WatchBundleRequest_Heartbeat) ProtoMessage() {}

func (x *WatchBundleRequest_Heartbeat) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WatchBundleRequest_Heartbeat.ProtoReflect.Descriptor instead.
func (*WatchBundleRequest_Heartbeat) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{6, 1}
}

func (x *WatchBundleRequest_Heartbeat) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *WatchBundleRequest_Heartbeat) GetActiveBundleId() string {
	if x != nil {
		return x.ActiveBundleId
	}
	return ""
}

type WatchBundleResponse_Reconnect struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Backoff       *durationpb.Duration   `protobuf:"bytes,1,opt,name=backoff,proto3" json:"backoff,omitempty"`
	Reason        string                 `protobuf:"bytes,2,opt,name=reason,proto3" json:"reason,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *WatchBundleResponse_Reconnect) Reset() {
	*x = WatchBundleResponse_Reconnect{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WatchBundleResponse_Reconnect) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WatchBundleResponse_Reconnect) ProtoMessage() {}

func (x *WatchBundleResponse_Reconnect) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WatchBundleResponse_Reconnect.ProtoReflect.Descriptor instead.
func (*WatchBundleResponse_Reconnect) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{7, 0}
}

func (x *WatchBundleResponse_Reconnect) GetBackoff() *durationpb.Duration {
	if x != nil {
		return x.Backoff
	}
	return nil
}

func (x *WatchBundleResponse_Reconnect) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

type WatchBundleResponse_BundleRemoved struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *WatchBundleResponse_BundleRemoved) Reset() {
	*x = WatchBundleResponse_BundleRemoved{}
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[13]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WatchBundleResponse_BundleRemoved) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WatchBundleResponse_BundleRemoved) ProtoMessage() {}

func (x *WatchBundleResponse_BundleRemoved) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[13]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WatchBundleResponse_BundleRemoved.ProtoReflect.Descriptor instead.
func (*WatchBundleResponse_BundleRemoved) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP(), []int{7, 1}
}

var File_cerbos_cloud_bundle_v2_bundle_proto protoreflect.FileDescriptor

const file_cerbos_cloud_bundle_v2_bundle_proto_rawDesc = "" +
	"\n" +
	"#cerbos/cloud/bundle/v2/bundle.proto\x12\x16cerbos.cloud.bundle.v2\x1a\x1bbuf/validate/validate.proto\x1a\x1dcerbos/cloud/pdp/v1/pdp.proto\x1a\x1bgoogle/api/visibility.proto\x1a\x1egoogle/protobuf/duration.proto\x1a\x1fgoogle/protobuf/timestamp.proto\"{\n" +
	"\x06Source\x12/\n" +
	"\rdeployment_id\x18\x01 \x01(\tB\b\xbaH\x05r\x03\x98\x01\fH\x00R\fdeploymentId\x12/\n" +
	"\rplayground_id\x18\x02 \x01(\tB\b\xbaH\x05r\x03\x98\x01\fH\x00R\fplaygroundIdB\x0f\n" +
	"\x06source\x12\x05\xbaH\x02\b\x01\"\xa7\x03\n" +
	"\n" +
	"BundleInfo\x12>\n" +
	"\x06source\x18\x01 \x01(\v2\x1e.cerbos.cloud.bundle.v2.SourceB\x06\xbaH\x03\xc8\x01\x01R\x06source\x12&\n" +
	"\n" +
	"input_hash\x18\x02 \x01(\fB\a\xbaH\x04z\x02h R\tinputHash\x12(\n" +
	"\voutput_hash\x18\x03 \x01(\fB\a\xbaH\x04z\x02h R\n" +
	"outputHash\x12%\n" +
	"\x0eencryption_key\x18\x04 \x01(\fR\rencryptionKey\x12P\n" +
	"\bsegments\x18\x05 \x03(\v2*.cerbos.cloud.bundle.v2.BundleInfo.SegmentB\b\xbaH\x05\x92\x01\x02\b\x01R\bsegments\x1a\x8d\x01\n" +
	"\aSegment\x12&\n" +
	"\n" +
	"segment_id\x18\x01 \x01(\rB\a\xbaH\x04*\x02 \x00R\tsegmentId\x12#\n" +
	"\bchecksum\x18\x02 \x01(\fB\a\xbaH\x04z\x02h R\bchecksum\x125\n" +
	"\rdownload_urls\x18\x03 \x03(\tB\x10\xbaH\r\x92\x01\n" +
	"\b\x01\x18\x01\"\x04r\x02\x10\x01R\fdownloadUrls\"E\n" +
	"\x04Meta\x12%\n" +
	"\tbundle_id\x18\x01 \x01(\tB\b\xbaH\x05r\x03\x98\x01\x10R\bbundleId\x12\x16\n" +
	"\x06source\x18\x02 \x01(\tR\x06source\"\x8d\x02\n" +
	"\bManifest\x12\x1f\n" +
	"\vapi_version\x18\x01 \x01(\tR\n" +
	"apiVersion\x12T\n" +
	"\fpolicy_index\x18\x02 \x03(\v21.cerbos.cloud.bundle.v2.Manifest.PolicyIndexEntryR\vpolicyIndex\x12\x18\n" +
	"\aschemas\x18\x03 \x03(\tR\aschemas\x120\n" +
	"\x04meta\x18\x04 \x01(\v2\x1c.cerbos.cloud.bundle.v2.MetaR\x04meta\x1a>\n" +
	"\x10PolicyIndexEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01\"\x92\x01\n" +
	"\x10GetBundleRequest\x12>\n" +
	"\x06pdp_id\x18\x01 \x01(\v2\x1f.cerbos.cloud.pdp.v1.IdentifierB\x06\xbaH\x03\xc8\x01\x01R\x05pdpId\x12>\n" +
	"\x06source\x18\x02 \x01(\v2\x1e.cerbos.cloud.bundle.v2.SourceB\x06\xbaH\x03\xc8\x01\x01R\x06source\"`\n" +
	"\x11GetBundleResponse\x12K\n" +
	"\vbundle_info\x18\x01 \x01(\v2\".cerbos.cloud.bundle.v2.BundleInfoB\x06\xbaH\x03\xc8\x01\x01R\n" +
	"bundleInfo\"\xcf\x03\n" +
	"\x12WatchBundleRequest\x12>\n" +
	"\x06pdp_id\x18\x01 \x01(\v2\x1f.cerbos.cloud.pdp.v1.IdentifierB\x06\xbaH\x03\xc8\x01\x01R\x05pdpId\x12H\n" +
	"\x05start\x18\x02 \x01(\v20.cerbos.cloud.bundle.v2.WatchBundleRequest.StartH\x00R\x05start\x12T\n" +
	"\theartbeat\x18\x03 \x01(\v24.cerbos.cloud.bundle.v2.WatchBundleRequest.HeartbeatH\x00R\theartbeat\x1aG\n" +
	"\x05Start\x12>\n" +
	"\x06source\x18\x01 \x01(\v2\x1e.cerbos.cloud.bundle.v2.SourceB\x06\xbaH\x03\xc8\x01\x01R\x06source\x1a\x88\x01\n" +
	"\tHeartbeat\x12G\n" +
	"\ttimestamp\x18\x01 \x01(\v2\x1a.google.protobuf.TimestampB\r\xbaH\n" +
	"\xc8\x01\x01\xb2\x01\x04J\x02\b<R\ttimestamp\x122\n" +
	"\x10active_bundle_id\x18\x02 \x01(\tB\b\xbaH\x05r\x03\x98\x01\x10R\x0eactiveBundleIdB\x05\n" +
	"\x03msg\"\x94\x03\n" +
	"\x13WatchBundleResponse\x12I\n" +
	"\rbundle_update\x18\x01 \x01(\v2\".cerbos.cloud.bundle.v2.BundleInfoH\x00R\fbundleUpdate\x12U\n" +
	"\treconnect\x18\x02 \x01(\v25.cerbos.cloud.bundle.v2.WatchBundleResponse.ReconnectH\x00R\treconnect\x12b\n" +
	"\x0ebundle_removed\x18\x03 \x01(\v29.cerbos.cloud.bundle.v2.WatchBundleResponse.BundleRemovedH\x00R\rbundleRemoved\x1aX\n" +
	"\tReconnect\x123\n" +
	"\abackoff\x18\x01 \x01(\v2\x19.google.protobuf.DurationR\abackoff\x12\x16\n" +
	"\x06reason\x18\x02 \x01(\tR\x06reason\x1a\x0f\n" +
	"\rBundleRemovedB\f\n" +
	"\x03msg\x12\x05\xbaH\x02\b\x012\xfd\x01\n" +
	"\x13CerbosBundleService\x12b\n" +
	"\tGetBundle\x12(.cerbos.cloud.bundle.v2.GetBundleRequest\x1a).cerbos.cloud.bundle.v2.GetBundleResponse\"\x00\x12l\n" +
	"\vWatchBundle\x12*.cerbos.cloud.bundle.v2.WatchBundleRequest\x1a+.cerbos.cloud.bundle.v2.WatchBundleResponse\"\x00(\x010\x01\x1a\x14\xfa\xd2\xe4\x93\x02\x0e\x12\fEXPERIMENTALB\x80\x01\n" +
	"\x1edev.cerbos.api.cloud.v2.bundleZAgithub.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2;bundlev2\xaa\x02\x1aCerbos.Api.Cloud.V2.Bundleb\x06proto3"

var (
	file_cerbos_cloud_bundle_v2_bundle_proto_rawDescOnce sync.Once
	file_cerbos_cloud_bundle_v2_bundle_proto_rawDescData []byte
)

func file_cerbos_cloud_bundle_v2_bundle_proto_rawDescGZIP() []byte {
	file_cerbos_cloud_bundle_v2_bundle_proto_rawDescOnce.Do(func() {
		file_cerbos_cloud_bundle_v2_bundle_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_cerbos_cloud_bundle_v2_bundle_proto_rawDesc), len(file_cerbos_cloud_bundle_v2_bundle_proto_rawDesc)))
	})
	return file_cerbos_cloud_bundle_v2_bundle_proto_rawDescData
}

var file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_cerbos_cloud_bundle_v2_bundle_proto_goTypes = []any{
	(*Source)(nil),                            // 0: cerbos.cloud.bundle.v2.Source
	(*BundleInfo)(nil),                        // 1: cerbos.cloud.bundle.v2.BundleInfo
	(*Meta)(nil),                              // 2: cerbos.cloud.bundle.v2.Meta
	(*Manifest)(nil),                          // 3: cerbos.cloud.bundle.v2.Manifest
	(*GetBundleRequest)(nil),                  // 4: cerbos.cloud.bundle.v2.GetBundleRequest
	(*GetBundleResponse)(nil),                 // 5: cerbos.cloud.bundle.v2.GetBundleResponse
	(*WatchBundleRequest)(nil),                // 6: cerbos.cloud.bundle.v2.WatchBundleRequest
	(*WatchBundleResponse)(nil),               // 7: cerbos.cloud.bundle.v2.WatchBundleResponse
	(*BundleInfo_Segment)(nil),                // 8: cerbos.cloud.bundle.v2.BundleInfo.Segment
	nil,                                       // 9: cerbos.cloud.bundle.v2.Manifest.PolicyIndexEntry
	(*WatchBundleRequest_Start)(nil),          // 10: cerbos.cloud.bundle.v2.WatchBundleRequest.Start
	(*WatchBundleRequest_Heartbeat)(nil),      // 11: cerbos.cloud.bundle.v2.WatchBundleRequest.Heartbeat
	(*WatchBundleResponse_Reconnect)(nil),     // 12: cerbos.cloud.bundle.v2.WatchBundleResponse.Reconnect
	(*WatchBundleResponse_BundleRemoved)(nil), // 13: cerbos.cloud.bundle.v2.WatchBundleResponse.BundleRemoved
	(*v1.Identifier)(nil),                     // 14: cerbos.cloud.pdp.v1.Identifier
	(*timestamppb.Timestamp)(nil),             // 15: google.protobuf.Timestamp
	(*durationpb.Duration)(nil),               // 16: google.protobuf.Duration
}
var file_cerbos_cloud_bundle_v2_bundle_proto_depIdxs = []int32{
	0,  // 0: cerbos.cloud.bundle.v2.BundleInfo.source:type_name -> cerbos.cloud.bundle.v2.Source
	8,  // 1: cerbos.cloud.bundle.v2.BundleInfo.segments:type_name -> cerbos.cloud.bundle.v2.BundleInfo.Segment
	9,  // 2: cerbos.cloud.bundle.v2.Manifest.policy_index:type_name -> cerbos.cloud.bundle.v2.Manifest.PolicyIndexEntry
	2,  // 3: cerbos.cloud.bundle.v2.Manifest.meta:type_name -> cerbos.cloud.bundle.v2.Meta
	14, // 4: cerbos.cloud.bundle.v2.GetBundleRequest.pdp_id:type_name -> cerbos.cloud.pdp.v1.Identifier
	0,  // 5: cerbos.cloud.bundle.v2.GetBundleRequest.source:type_name -> cerbos.cloud.bundle.v2.Source
	1,  // 6: cerbos.cloud.bundle.v2.GetBundleResponse.bundle_info:type_name -> cerbos.cloud.bundle.v2.BundleInfo
	14, // 7: cerbos.cloud.bundle.v2.WatchBundleRequest.pdp_id:type_name -> cerbos.cloud.pdp.v1.Identifier
	10, // 8: cerbos.cloud.bundle.v2.WatchBundleRequest.start:type_name -> cerbos.cloud.bundle.v2.WatchBundleRequest.Start
	11, // 9: cerbos.cloud.bundle.v2.WatchBundleRequest.heartbeat:type_name -> cerbos.cloud.bundle.v2.WatchBundleRequest.Heartbeat
	1,  // 10: cerbos.cloud.bundle.v2.WatchBundleResponse.bundle_update:type_name -> cerbos.cloud.bundle.v2.BundleInfo
	12, // 11: cerbos.cloud.bundle.v2.WatchBundleResponse.reconnect:type_name -> cerbos.cloud.bundle.v2.WatchBundleResponse.Reconnect
	13, // 12: cerbos.cloud.bundle.v2.WatchBundleResponse.bundle_removed:type_name -> cerbos.cloud.bundle.v2.WatchBundleResponse.BundleRemoved
	0,  // 13: cerbos.cloud.bundle.v2.WatchBundleRequest.Start.source:type_name -> cerbos.cloud.bundle.v2.Source
	15, // 14: cerbos.cloud.bundle.v2.WatchBundleRequest.Heartbeat.timestamp:type_name -> google.protobuf.Timestamp
	16, // 15: cerbos.cloud.bundle.v2.WatchBundleResponse.Reconnect.backoff:type_name -> google.protobuf.Duration
	4,  // 16: cerbos.cloud.bundle.v2.CerbosBundleService.GetBundle:input_type -> cerbos.cloud.bundle.v2.GetBundleRequest
	6,  // 17: cerbos.cloud.bundle.v2.CerbosBundleService.WatchBundle:input_type -> cerbos.cloud.bundle.v2.WatchBundleRequest
	5,  // 18: cerbos.cloud.bundle.v2.CerbosBundleService.GetBundle:output_type -> cerbos.cloud.bundle.v2.GetBundleResponse
	7,  // 19: cerbos.cloud.bundle.v2.CerbosBundleService.WatchBundle:output_type -> cerbos.cloud.bundle.v2.WatchBundleResponse
	18, // [18:20] is the sub-list for method output_type
	16, // [16:18] is the sub-list for method input_type
	16, // [16:16] is the sub-list for extension type_name
	16, // [16:16] is the sub-list for extension extendee
	0,  // [0:16] is the sub-list for field type_name
}

func init() { file_cerbos_cloud_bundle_v2_bundle_proto_init() }
func file_cerbos_cloud_bundle_v2_bundle_proto_init() {
	if File_cerbos_cloud_bundle_v2_bundle_proto != nil {
		return
	}
	file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[0].OneofWrappers = []any{
		(*Source_DeploymentId)(nil),
		(*Source_PlaygroundId)(nil),
	}
	file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[6].OneofWrappers = []any{
		(*WatchBundleRequest_Start_)(nil),
		(*WatchBundleRequest_Heartbeat_)(nil),
	}
	file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes[7].OneofWrappers = []any{
		(*WatchBundleResponse_BundleUpdate)(nil),
		(*WatchBundleResponse_Reconnect_)(nil),
		(*WatchBundleResponse_BundleRemoved_)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_cerbos_cloud_bundle_v2_bundle_proto_rawDesc), len(file_cerbos_cloud_bundle_v2_bundle_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cerbos_cloud_bundle_v2_bundle_proto_goTypes,
		DependencyIndexes: file_cerbos_cloud_bundle_v2_bundle_proto_depIdxs,
		MessageInfos:      file_cerbos_cloud_bundle_v2_bundle_proto_msgTypes,
	}.Build()
	File_cerbos_cloud_bundle_v2_bundle_proto = out.File
	file_cerbos_cloud_bundle_v2_bundle_proto_goTypes = nil
	file_cerbos_cloud_bundle_v2_bundle_proto_depIdxs = nil
}
