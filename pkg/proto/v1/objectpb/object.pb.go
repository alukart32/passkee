// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.22.2
// source: object.proto

package objectpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	fieldmaskpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ObjectType int32

const (
	ObjectType_UNDEFINED   ObjectType = 0
	ObjectType_OBJECT_TEXT ObjectType = 1
	ObjectType_OBJECT_BIN  ObjectType = 2
)

// Enum value maps for ObjectType.
var (
	ObjectType_name = map[int32]string{
		0: "UNDEFINED",
		1: "OBJECT_TEXT",
		2: "OBJECT_BIN",
	}
	ObjectType_value = map[string]int32{
		"UNDEFINED":   0,
		"OBJECT_TEXT": 1,
		"OBJECT_BIN":  2,
	}
)

func (x ObjectType) Enum() *ObjectType {
	p := new(ObjectType)
	*p = x
	return p
}

func (x ObjectType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ObjectType) Descriptor() protoreflect.EnumDescriptor {
	return file_object_proto_enumTypes[0].Descriptor()
}

func (ObjectType) Type() protoreflect.EnumType {
	return &file_object_proto_enumTypes[0]
}

func (x ObjectType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ObjectType.Descriptor instead.
func (ObjectType) EnumDescriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{0}
}

type UploadObjectRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Data:
	//
	//	*UploadObjectRequest_Info
	//	*UploadObjectRequest_Chunk
	Data isUploadObjectRequest_Data `protobuf_oneof:"data"`
}

func (x *UploadObjectRequest) Reset() {
	*x = UploadObjectRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UploadObjectRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UploadObjectRequest) ProtoMessage() {}

func (x *UploadObjectRequest) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UploadObjectRequest.ProtoReflect.Descriptor instead.
func (*UploadObjectRequest) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{0}
}

func (m *UploadObjectRequest) GetData() isUploadObjectRequest_Data {
	if m != nil {
		return m.Data
	}
	return nil
}

func (x *UploadObjectRequest) GetInfo() *UploadObjectRequest_ObjectInfo {
	if x, ok := x.GetData().(*UploadObjectRequest_Info); ok {
		return x.Info
	}
	return nil
}

func (x *UploadObjectRequest) GetChunk() *Chunk {
	if x, ok := x.GetData().(*UploadObjectRequest_Chunk); ok {
		return x.Chunk
	}
	return nil
}

type isUploadObjectRequest_Data interface {
	isUploadObjectRequest_Data()
}

type UploadObjectRequest_Info struct {
	Info *UploadObjectRequest_ObjectInfo `protobuf:"bytes,1,opt,name=info,proto3,oneof"`
}

type UploadObjectRequest_Chunk struct {
	Chunk *Chunk `protobuf:"bytes,2,opt,name=chunk,proto3,oneof"`
}

func (*UploadObjectRequest_Info) isUploadObjectRequest_Data() {}

func (*UploadObjectRequest_Chunk) isUploadObjectRequest_Data() {}

type Chunk struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"` // 4096 bytes
}

func (x *Chunk) Reset() {
	*x = Chunk{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Chunk) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Chunk) ProtoMessage() {}

func (x *Chunk) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Chunk.ProtoReflect.Descriptor instead.
func (*Chunk) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{1}
}

func (x *Chunk) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type DownloadObjectRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name []byte     `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Typ  ObjectType `protobuf:"varint,2,opt,name=typ,proto3,enum=dataobject.v1.ObjectType" json:"typ,omitempty"`
}

func (x *DownloadObjectRequest) Reset() {
	*x = DownloadObjectRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DownloadObjectRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DownloadObjectRequest) ProtoMessage() {}

func (x *DownloadObjectRequest) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DownloadObjectRequest.ProtoReflect.Descriptor instead.
func (*DownloadObjectRequest) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{2}
}

func (x *DownloadObjectRequest) GetName() []byte {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *DownloadObjectRequest) GetTyp() ObjectType {
	if x != nil {
		return x.Typ
	}
	return ObjectType_UNDEFINED
}

type DownloadObjectResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Data:
	//
	//	*DownloadObjectResponse_Info
	//	*DownloadObjectResponse_Chunk
	Data isDownloadObjectResponse_Data `protobuf_oneof:"data"`
}

func (x *DownloadObjectResponse) Reset() {
	*x = DownloadObjectResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DownloadObjectResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DownloadObjectResponse) ProtoMessage() {}

func (x *DownloadObjectResponse) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DownloadObjectResponse.ProtoReflect.Descriptor instead.
func (*DownloadObjectResponse) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{3}
}

func (m *DownloadObjectResponse) GetData() isDownloadObjectResponse_Data {
	if m != nil {
		return m.Data
	}
	return nil
}

func (x *DownloadObjectResponse) GetInfo() *DownloadObjectResponse_ObjectInfo {
	if x, ok := x.GetData().(*DownloadObjectResponse_Info); ok {
		return x.Info
	}
	return nil
}

func (x *DownloadObjectResponse) GetChunk() *Chunk {
	if x, ok := x.GetData().(*DownloadObjectResponse_Chunk); ok {
		return x.Chunk
	}
	return nil
}

type isDownloadObjectResponse_Data interface {
	isDownloadObjectResponse_Data()
}

type DownloadObjectResponse_Info struct {
	Info *DownloadObjectResponse_ObjectInfo `protobuf:"bytes,1,opt,name=info,proto3,oneof"`
}

type DownloadObjectResponse_Chunk struct {
	Chunk *Chunk `protobuf:"bytes,2,opt,name=chunk,proto3,oneof"`
}

func (*DownloadObjectResponse_Info) isDownloadObjectResponse_Data() {}

func (*DownloadObjectResponse_Chunk) isDownloadObjectResponse_Data() {}

type UpdateObjectInfoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name       []byte                              `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Typ        ObjectType                          `protobuf:"varint,2,opt,name=typ,proto3,enum=dataobject.v1.ObjectType" json:"typ,omitempty"`
	Info       *UpdateObjectInfoRequest_ObjectInfo `protobuf:"bytes,3,opt,name=info,proto3" json:"info,omitempty"`
	UpdateMask *fieldmaskpb.FieldMask              `protobuf:"bytes,4,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
}

func (x *UpdateObjectInfoRequest) Reset() {
	*x = UpdateObjectInfoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateObjectInfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateObjectInfoRequest) ProtoMessage() {}

func (x *UpdateObjectInfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateObjectInfoRequest.ProtoReflect.Descriptor instead.
func (*UpdateObjectInfoRequest) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{4}
}

func (x *UpdateObjectInfoRequest) GetName() []byte {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *UpdateObjectInfoRequest) GetTyp() ObjectType {
	if x != nil {
		return x.Typ
	}
	return ObjectType_UNDEFINED
}

func (x *UpdateObjectInfoRequest) GetInfo() *UpdateObjectInfoRequest_ObjectInfo {
	if x != nil {
		return x.Info
	}
	return nil
}

func (x *UpdateObjectInfoRequest) GetUpdateMask() *fieldmaskpb.FieldMask {
	if x != nil {
		return x.UpdateMask
	}
	return nil
}

type IndexObjectsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Infos []*IndexObjectsResponse_ObjectInfo `protobuf:"bytes,1,rep,name=infos,proto3" json:"infos,omitempty"`
}

func (x *IndexObjectsResponse) Reset() {
	*x = IndexObjectsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IndexObjectsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IndexObjectsResponse) ProtoMessage() {}

func (x *IndexObjectsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IndexObjectsResponse.ProtoReflect.Descriptor instead.
func (*IndexObjectsResponse) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{5}
}

func (x *IndexObjectsResponse) GetInfos() []*IndexObjectsResponse_ObjectInfo {
	if x != nil {
		return x.Infos
	}
	return nil
}

type DeleteObjectRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name []byte     `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Typ  ObjectType `protobuf:"varint,2,opt,name=typ,proto3,enum=dataobject.v1.ObjectType" json:"typ,omitempty"`
}

func (x *DeleteObjectRequest) Reset() {
	*x = DeleteObjectRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteObjectRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteObjectRequest) ProtoMessage() {}

func (x *DeleteObjectRequest) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteObjectRequest.ProtoReflect.Descriptor instead.
func (*DeleteObjectRequest) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{6}
}

func (x *DeleteObjectRequest) GetName() []byte {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *DeleteObjectRequest) GetTyp() ObjectType {
	if x != nil {
		return x.Typ
	}
	return ObjectType_UNDEFINED
}

type UploadObjectRequest_ObjectInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  []byte     `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Typ   ObjectType `protobuf:"varint,2,opt,name=typ,proto3,enum=dataobject.v1.ObjectType" json:"typ,omitempty"`
	Notes []byte     `protobuf:"bytes,3,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *UploadObjectRequest_ObjectInfo) Reset() {
	*x = UploadObjectRequest_ObjectInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UploadObjectRequest_ObjectInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UploadObjectRequest_ObjectInfo) ProtoMessage() {}

func (x *UploadObjectRequest_ObjectInfo) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UploadObjectRequest_ObjectInfo.ProtoReflect.Descriptor instead.
func (*UploadObjectRequest_ObjectInfo) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{0, 0}
}

func (x *UploadObjectRequest_ObjectInfo) GetName() []byte {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *UploadObjectRequest_ObjectInfo) GetTyp() ObjectType {
	if x != nil {
		return x.Typ
	}
	return ObjectType_UNDEFINED
}

func (x *UploadObjectRequest_ObjectInfo) GetNotes() []byte {
	if x != nil {
		return x.Notes
	}
	return nil
}

type DownloadObjectResponse_ObjectInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  []byte `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id    []byte `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Notes []byte `protobuf:"bytes,3,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *DownloadObjectResponse_ObjectInfo) Reset() {
	*x = DownloadObjectResponse_ObjectInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DownloadObjectResponse_ObjectInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DownloadObjectResponse_ObjectInfo) ProtoMessage() {}

func (x *DownloadObjectResponse_ObjectInfo) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DownloadObjectResponse_ObjectInfo.ProtoReflect.Descriptor instead.
func (*DownloadObjectResponse_ObjectInfo) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{3, 0}
}

func (x *DownloadObjectResponse_ObjectInfo) GetName() []byte {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *DownloadObjectResponse_ObjectInfo) GetId() []byte {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *DownloadObjectResponse_ObjectInfo) GetNotes() []byte {
	if x != nil {
		return x.Notes
	}
	return nil
}

type UpdateObjectInfoRequest_ObjectInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  []byte `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id    []byte `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Notes []byte `protobuf:"bytes,3,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *UpdateObjectInfoRequest_ObjectInfo) Reset() {
	*x = UpdateObjectInfoRequest_ObjectInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateObjectInfoRequest_ObjectInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateObjectInfoRequest_ObjectInfo) ProtoMessage() {}

func (x *UpdateObjectInfoRequest_ObjectInfo) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateObjectInfoRequest_ObjectInfo.ProtoReflect.Descriptor instead.
func (*UpdateObjectInfoRequest_ObjectInfo) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{4, 0}
}

func (x *UpdateObjectInfoRequest_ObjectInfo) GetName() []byte {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *UpdateObjectInfoRequest_ObjectInfo) GetId() []byte {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *UpdateObjectInfoRequest_ObjectInfo) GetNotes() []byte {
	if x != nil {
		return x.Notes
	}
	return nil
}

type IndexObjectsResponse_ObjectInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name []byte     `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Typ  ObjectType `protobuf:"varint,2,opt,name=typ,proto3,enum=dataobject.v1.ObjectType" json:"typ,omitempty"`
}

func (x *IndexObjectsResponse_ObjectInfo) Reset() {
	*x = IndexObjectsResponse_ObjectInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_object_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IndexObjectsResponse_ObjectInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IndexObjectsResponse_ObjectInfo) ProtoMessage() {}

func (x *IndexObjectsResponse_ObjectInfo) ProtoReflect() protoreflect.Message {
	mi := &file_object_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IndexObjectsResponse_ObjectInfo.ProtoReflect.Descriptor instead.
func (*IndexObjectsResponse_ObjectInfo) Descriptor() ([]byte, []int) {
	return file_object_proto_rawDescGZIP(), []int{5, 0}
}

func (x *IndexObjectsResponse_ObjectInfo) GetName() []byte {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *IndexObjectsResponse_ObjectInfo) GetTyp() ObjectType {
	if x != nil {
		return x.Typ
	}
	return ObjectType_UNDEFINED
}

var File_object_proto protoreflect.FileDescriptor

var file_object_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d,
	0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65,
	0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x66, 0x69, 0x65, 0x6c,
	0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x84, 0x02, 0x0a,
	0x13, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x43, 0x0a, 0x04, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e,
	0x76, 0x31, 0x2e, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66,
	0x6f, 0x48, 0x00, 0x52, 0x04, 0x69, 0x6e, 0x66, 0x6f, 0x12, 0x2c, 0x0a, 0x05, 0x63, 0x68, 0x75,
	0x6e, 0x6b, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x48, 0x00,
	0x52, 0x05, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x1a, 0x72, 0x0a, 0x0a, 0x4f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2b, 0x0a, 0x03, 0x74, 0x79, 0x70,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70,
	0x65, 0x52, 0x03, 0x74, 0x79, 0x70, 0x12, 0x19, 0x0a, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01,
	0x01, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x42, 0x06, 0x0a, 0x04, 0x64,
	0x61, 0x74, 0x61, 0x22, 0x1b, 0x0a, 0x05, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x12, 0x12, 0x0a, 0x04,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61,
	0x22, 0x58, 0x0a, 0x15, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x4f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2b, 0x0a,
	0x03, 0x74, 0x79, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x64, 0x61, 0x74,
	0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x54, 0x79, 0x70, 0x65, 0x52, 0x03, 0x74, 0x79, 0x70, 0x22, 0xed, 0x01, 0x0a, 0x16, 0x44,
	0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x46, 0x0a, 0x04, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x2e, 0x76, 0x31, 0x2e, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x4f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x49, 0x6e, 0x66, 0x6f, 0x48, 0x00, 0x52, 0x04, 0x69, 0x6e, 0x66, 0x6f, 0x12, 0x2c, 0x0a,
	0x05, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x64,
	0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x75,
	0x6e, 0x6b, 0x48, 0x00, 0x52, 0x05, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x1a, 0x55, 0x0a, 0x0a, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x64, 0x12, 0x19, 0x0a,
	0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x05,
	0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6e, 0x6f, 0x74,
	0x65, 0x73, 0x42, 0x06, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0xb5, 0x02, 0x0a, 0x17, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2b, 0x0a, 0x03, 0x74, 0x79,
	0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x03, 0x74, 0x79, 0x70, 0x12, 0x45, 0x0a, 0x04, 0x69, 0x6e, 0x66, 0x6f, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x4f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x04, 0x69, 0x6e, 0x66, 0x6f, 0x12, 0x3b,
	0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x73, 0x6b, 0x52,
	0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4d, 0x61, 0x73, 0x6b, 0x1a, 0x55, 0x0a, 0x0a, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x64, 0x12, 0x19, 0x0a,
	0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x05,
	0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6e, 0x6f, 0x74,
	0x65, 0x73, 0x22, 0xab, 0x01, 0x0a, 0x14, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x4f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x44, 0x0a, 0x05, 0x69,
	0x6e, 0x66, 0x6f, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x64, 0x61, 0x74,
	0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x6e, 0x64, 0x65, 0x78,
	0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e,
	0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x69, 0x6e, 0x66, 0x6f,
	0x73, 0x1a, 0x4d, 0x0a, 0x0a, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x2b, 0x0a, 0x03, 0x74, 0x79, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x19, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31,
	0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x52, 0x03, 0x74, 0x79, 0x70,
	0x22, 0x56, 0x0a, 0x13, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2b, 0x0a, 0x03, 0x74,
	0x79, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x03, 0x74, 0x79, 0x70, 0x2a, 0x3c, 0x0a, 0x0a, 0x4f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x55, 0x4e, 0x44, 0x45, 0x46, 0x49,
	0x4e, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0f, 0x0a, 0x0b, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54, 0x5f,
	0x54, 0x45, 0x58, 0x54, 0x10, 0x01, 0x12, 0x0e, 0x0a, 0x0a, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54,
	0x5f, 0x42, 0x49, 0x4e, 0x10, 0x02, 0x32, 0xa9, 0x03, 0x0a, 0x0b, 0x4f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x56, 0x61, 0x75, 0x6c, 0x74, 0x12, 0x4c, 0x0a, 0x0c, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64,
	0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x22, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x4f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x28, 0x01, 0x12, 0x5f, 0x0a, 0x0e, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64,
	0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x24, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e, 0x64,
	0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x6f, 0x77,
	0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x52, 0x0a, 0x10, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x26, 0x2e, 0x64, 0x61, 0x74, 0x61,
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x4b, 0x0a, 0x0c, 0x49, 0x6e, 0x64,
	0x65, 0x78, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74,
	0x79, 0x1a, 0x23, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x76,
	0x31, 0x2e, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4a, 0x0a, 0x0c, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x22, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x42, 0x17, 0x5a, 0x15, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x76, 0x31, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_object_proto_rawDescOnce sync.Once
	file_object_proto_rawDescData = file_object_proto_rawDesc
)

func file_object_proto_rawDescGZIP() []byte {
	file_object_proto_rawDescOnce.Do(func() {
		file_object_proto_rawDescData = protoimpl.X.CompressGZIP(file_object_proto_rawDescData)
	})
	return file_object_proto_rawDescData
}

var file_object_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_object_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_object_proto_goTypes = []interface{}{
	(ObjectType)(0),                            // 0: dataobject.v1.ObjectType
	(*UploadObjectRequest)(nil),                // 1: dataobject.v1.UploadObjectRequest
	(*Chunk)(nil),                              // 2: dataobject.v1.Chunk
	(*DownloadObjectRequest)(nil),              // 3: dataobject.v1.DownloadObjectRequest
	(*DownloadObjectResponse)(nil),             // 4: dataobject.v1.DownloadObjectResponse
	(*UpdateObjectInfoRequest)(nil),            // 5: dataobject.v1.UpdateObjectInfoRequest
	(*IndexObjectsResponse)(nil),               // 6: dataobject.v1.IndexObjectsResponse
	(*DeleteObjectRequest)(nil),                // 7: dataobject.v1.DeleteObjectRequest
	(*UploadObjectRequest_ObjectInfo)(nil),     // 8: dataobject.v1.UploadObjectRequest.ObjectInfo
	(*DownloadObjectResponse_ObjectInfo)(nil),  // 9: dataobject.v1.DownloadObjectResponse.ObjectInfo
	(*UpdateObjectInfoRequest_ObjectInfo)(nil), // 10: dataobject.v1.UpdateObjectInfoRequest.ObjectInfo
	(*IndexObjectsResponse_ObjectInfo)(nil),    // 11: dataobject.v1.IndexObjectsResponse.ObjectInfo
	(*fieldmaskpb.FieldMask)(nil),              // 12: google.protobuf.FieldMask
	(*emptypb.Empty)(nil),                      // 13: google.protobuf.Empty
}
var file_object_proto_depIdxs = []int32{
	8,  // 0: dataobject.v1.UploadObjectRequest.info:type_name -> dataobject.v1.UploadObjectRequest.ObjectInfo
	2,  // 1: dataobject.v1.UploadObjectRequest.chunk:type_name -> dataobject.v1.Chunk
	0,  // 2: dataobject.v1.DownloadObjectRequest.typ:type_name -> dataobject.v1.ObjectType
	9,  // 3: dataobject.v1.DownloadObjectResponse.info:type_name -> dataobject.v1.DownloadObjectResponse.ObjectInfo
	2,  // 4: dataobject.v1.DownloadObjectResponse.chunk:type_name -> dataobject.v1.Chunk
	0,  // 5: dataobject.v1.UpdateObjectInfoRequest.typ:type_name -> dataobject.v1.ObjectType
	10, // 6: dataobject.v1.UpdateObjectInfoRequest.info:type_name -> dataobject.v1.UpdateObjectInfoRequest.ObjectInfo
	12, // 7: dataobject.v1.UpdateObjectInfoRequest.update_mask:type_name -> google.protobuf.FieldMask
	11, // 8: dataobject.v1.IndexObjectsResponse.infos:type_name -> dataobject.v1.IndexObjectsResponse.ObjectInfo
	0,  // 9: dataobject.v1.DeleteObjectRequest.typ:type_name -> dataobject.v1.ObjectType
	0,  // 10: dataobject.v1.UploadObjectRequest.ObjectInfo.typ:type_name -> dataobject.v1.ObjectType
	0,  // 11: dataobject.v1.IndexObjectsResponse.ObjectInfo.typ:type_name -> dataobject.v1.ObjectType
	1,  // 12: dataobject.v1.ObjectVault.UploadObject:input_type -> dataobject.v1.UploadObjectRequest
	3,  // 13: dataobject.v1.ObjectVault.DownloadObject:input_type -> dataobject.v1.DownloadObjectRequest
	5,  // 14: dataobject.v1.ObjectVault.UpdateObjectInfo:input_type -> dataobject.v1.UpdateObjectInfoRequest
	13, // 15: dataobject.v1.ObjectVault.IndexObjects:input_type -> google.protobuf.Empty
	7,  // 16: dataobject.v1.ObjectVault.DeleteObject:input_type -> dataobject.v1.DeleteObjectRequest
	13, // 17: dataobject.v1.ObjectVault.UploadObject:output_type -> google.protobuf.Empty
	4,  // 18: dataobject.v1.ObjectVault.DownloadObject:output_type -> dataobject.v1.DownloadObjectResponse
	13, // 19: dataobject.v1.ObjectVault.UpdateObjectInfo:output_type -> google.protobuf.Empty
	6,  // 20: dataobject.v1.ObjectVault.IndexObjects:output_type -> dataobject.v1.IndexObjectsResponse
	13, // 21: dataobject.v1.ObjectVault.DeleteObject:output_type -> google.protobuf.Empty
	17, // [17:22] is the sub-list for method output_type
	12, // [12:17] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_object_proto_init() }
func file_object_proto_init() {
	if File_object_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_object_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UploadObjectRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Chunk); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DownloadObjectRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DownloadObjectResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateObjectInfoRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IndexObjectsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteObjectRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UploadObjectRequest_ObjectInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DownloadObjectResponse_ObjectInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateObjectInfoRequest_ObjectInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_object_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IndexObjectsResponse_ObjectInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_object_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*UploadObjectRequest_Info)(nil),
		(*UploadObjectRequest_Chunk)(nil),
	}
	file_object_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*DownloadObjectResponse_Info)(nil),
		(*DownloadObjectResponse_Chunk)(nil),
	}
	file_object_proto_msgTypes[7].OneofWrappers = []interface{}{}
	file_object_proto_msgTypes[8].OneofWrappers = []interface{}{}
	file_object_proto_msgTypes[9].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_object_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_object_proto_goTypes,
		DependencyIndexes: file_object_proto_depIdxs,
		EnumInfos:         file_object_proto_enumTypes,
		MessageInfos:      file_object_proto_msgTypes,
	}.Build()
	File_object_proto = out.File
	file_object_proto_rawDesc = nil
	file_object_proto_goTypes = nil
	file_object_proto_depIdxs = nil
}