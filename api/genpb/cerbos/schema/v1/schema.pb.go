// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        (unknown)
// source: cerbos/schema/v1/schema.proto

package schemav1

import (
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ValidationError_Source int32

const (
	ValidationError_SOURCE_UNSPECIFIED ValidationError_Source = 0
	ValidationError_SOURCE_PRINCIPAL   ValidationError_Source = 1
	ValidationError_SOURCE_RESOURCE    ValidationError_Source = 2
)

// Enum value maps for ValidationError_Source.
var (
	ValidationError_Source_name = map[int32]string{
		0: "SOURCE_UNSPECIFIED",
		1: "SOURCE_PRINCIPAL",
		2: "SOURCE_RESOURCE",
	}
	ValidationError_Source_value = map[string]int32{
		"SOURCE_UNSPECIFIED": 0,
		"SOURCE_PRINCIPAL":   1,
		"SOURCE_RESOURCE":    2,
	}
)

func (x ValidationError_Source) Enum() *ValidationError_Source {
	p := new(ValidationError_Source)
	*p = x
	return p
}

func (x ValidationError_Source) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ValidationError_Source) Descriptor() protoreflect.EnumDescriptor {
	return file_cerbos_schema_v1_schema_proto_enumTypes[0].Descriptor()
}

func (ValidationError_Source) Type() protoreflect.EnumType {
	return &file_cerbos_schema_v1_schema_proto_enumTypes[0]
}

func (x ValidationError_Source) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ValidationError_Source.Descriptor instead.
func (ValidationError_Source) EnumDescriptor() ([]byte, []int) {
	return file_cerbos_schema_v1_schema_proto_rawDescGZIP(), []int{0, 0}
}

type ValidationError struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Path    string                 `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	Message string                 `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	Source  ValidationError_Source `protobuf:"varint,3,opt,name=source,proto3,enum=cerbos.schema.v1.ValidationError_Source" json:"source,omitempty"`
}

func (x *ValidationError) Reset() {
	*x = ValidationError{}
	mi := &file_cerbos_schema_v1_schema_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ValidationError) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidationError) ProtoMessage() {}

func (x *ValidationError) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_schema_v1_schema_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidationError.ProtoReflect.Descriptor instead.
func (*ValidationError) Descriptor() ([]byte, []int) {
	return file_cerbos_schema_v1_schema_proto_rawDescGZIP(), []int{0}
}

func (x *ValidationError) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *ValidationError) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *ValidationError) GetSource() ValidationError_Source {
	if x != nil {
		return x.Source
	}
	return ValidationError_SOURCE_UNSPECIFIED
}

type Schema struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Definition []byte `protobuf:"bytes,2,opt,name=definition,proto3" json:"definition,omitempty"`
}

func (x *Schema) Reset() {
	*x = Schema{}
	mi := &file_cerbos_schema_v1_schema_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Schema) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Schema) ProtoMessage() {}

func (x *Schema) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_schema_v1_schema_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Schema.ProtoReflect.Descriptor instead.
func (*Schema) Descriptor() ([]byte, []int) {
	return file_cerbos_schema_v1_schema_proto_rawDescGZIP(), []int{1}
}

func (x *Schema) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Schema) GetDefinition() []byte {
	if x != nil {
		return x.Definition
	}
	return nil
}

var File_cerbos_schema_v1_schema_proto protoreflect.FileDescriptor

var file_cerbos_schema_v1_schema_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2f, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2f,
	0x76, 0x31, 0x2f, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x10, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x76,
	0x31, 0x1a, 0x1b, 0x62, 0x75, 0x66, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64,
	0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e,
	0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xce, 0x01, 0x0a, 0x0f, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x72,
	0x72, 0x6f, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x40, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x28, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d,
	0x61, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45,
	0x72, 0x72, 0x6f, 0x72, 0x2e, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x06, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x22, 0x4b, 0x0a, 0x06, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x16, 0x0a,
	0x12, 0x53, 0x4f, 0x55, 0x52, 0x43, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46,
	0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x14, 0x0a, 0x10, 0x53, 0x4f, 0x55, 0x52, 0x43, 0x45, 0x5f,
	0x50, 0x52, 0x49, 0x4e, 0x43, 0x49, 0x50, 0x41, 0x4c, 0x10, 0x01, 0x12, 0x13, 0x0a, 0x0f, 0x53,
	0x4f, 0x55, 0x52, 0x43, 0x45, 0x5f, 0x52, 0x45, 0x53, 0x4f, 0x55, 0x52, 0x43, 0x45, 0x10, 0x02,
	0x22, 0xcf, 0x01, 0x0a, 0x06, 0x53, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x12, 0x57, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x47, 0x92, 0x41, 0x34, 0x32, 0x20, 0x55, 0x6e,
	0x69, 0x71, 0x75, 0x65, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x20,
	0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x4a, 0x10,
	0x22, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x6a, 0x73, 0x6f, 0x6e, 0x22,
	0xe0, 0x41, 0x02, 0xba, 0x48, 0x0a, 0xc8, 0x01, 0x01, 0x72, 0x05, 0x10, 0x01, 0x18, 0xff, 0x01,
	0x52, 0x02, 0x69, 0x64, 0x12, 0x6c, 0x0a, 0x0a, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x4c, 0x92, 0x41, 0x3c, 0x32, 0x16, 0x4a,
	0x53, 0x4f, 0x4e, 0x20, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x20, 0x64, 0x65, 0x66, 0x69, 0x6e,
	0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4a, 0x22, 0x7b, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x22,
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x22, 0x2c, 0x20, 0x22, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72,
	0x74, 0x69, 0x65, 0x73, 0x22, 0x3a, 0x7b, 0x7d, 0x7d, 0xe0, 0x41, 0x02, 0xba, 0x48, 0x07, 0xc8,
	0x01, 0x01, 0x7a, 0x02, 0x10, 0x0a, 0x52, 0x0a, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x42, 0x6f, 0x0a, 0x18, 0x64, 0x65, 0x76, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x5a, 0x3c,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x65, 0x72, 0x62, 0x6f,
	0x73, 0x2f, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e,
	0x70, 0x62, 0x2f, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2f, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61,
	0x2f, 0x76, 0x31, 0x3b, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x76, 0x31, 0xaa, 0x02, 0x14, 0x43,
	0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x41, 0x70, 0x69, 0x2e, 0x56, 0x31, 0x2e, 0x53, 0x63, 0x68,
	0x65, 0x6d, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cerbos_schema_v1_schema_proto_rawDescOnce sync.Once
	file_cerbos_schema_v1_schema_proto_rawDescData = file_cerbos_schema_v1_schema_proto_rawDesc
)

func file_cerbos_schema_v1_schema_proto_rawDescGZIP() []byte {
	file_cerbos_schema_v1_schema_proto_rawDescOnce.Do(func() {
		file_cerbos_schema_v1_schema_proto_rawDescData = protoimpl.X.CompressGZIP(file_cerbos_schema_v1_schema_proto_rawDescData)
	})
	return file_cerbos_schema_v1_schema_proto_rawDescData
}

var file_cerbos_schema_v1_schema_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_cerbos_schema_v1_schema_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_cerbos_schema_v1_schema_proto_goTypes = []any{
	(ValidationError_Source)(0), // 0: cerbos.schema.v1.ValidationError.Source
	(*ValidationError)(nil),     // 1: cerbos.schema.v1.ValidationError
	(*Schema)(nil),              // 2: cerbos.schema.v1.Schema
}
var file_cerbos_schema_v1_schema_proto_depIdxs = []int32{
	0, // 0: cerbos.schema.v1.ValidationError.source:type_name -> cerbos.schema.v1.ValidationError.Source
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_cerbos_schema_v1_schema_proto_init() }
func file_cerbos_schema_v1_schema_proto_init() {
	if File_cerbos_schema_v1_schema_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cerbos_schema_v1_schema_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cerbos_schema_v1_schema_proto_goTypes,
		DependencyIndexes: file_cerbos_schema_v1_schema_proto_depIdxs,
		EnumInfos:         file_cerbos_schema_v1_schema_proto_enumTypes,
		MessageInfos:      file_cerbos_schema_v1_schema_proto_msgTypes,
	}.Build()
	File_cerbos_schema_v1_schema_proto = out.File
	file_cerbos_schema_v1_schema_proto_rawDesc = nil
	file_cerbos_schema_v1_schema_proto_goTypes = nil
	file_cerbos_schema_v1_schema_proto_depIdxs = nil
}
