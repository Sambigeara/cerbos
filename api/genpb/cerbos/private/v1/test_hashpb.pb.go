// Code generated by protoc-gen-go-hashpb. Do not edit.
// protoc-gen-go-hashpb v0.2.0
// Source: cerbos/private/v1/test.proto

package privatev1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *EngineTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_EngineTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_PlanResourcesCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_PlanResourcesCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_CheckResourceSetCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_CheckResourceSetCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_CheckResourceBatchCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_CheckResourceBatchCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_CheckResourcesCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_CheckResourcesCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_PlaygroundValidateCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_PlaygroundValidateCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_PlaygroundTestCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_PlaygroundTestCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_PlaygroundEvaluateCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_PlaygroundEvaluateCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_PlaygroundProxyCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_PlaygroundProxyCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_AdminAddOrUpdatePolicyCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_AdminAddOrUpdatePolicyCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_AdminAddOrUpdateSchemaCall) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_AdminAddOrUpdateSchemaCall_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerTestCase_Status) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ServerTestCase_Status_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *IndexBuilderTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_IndexBuilderTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *IndexBuilderTestCase_CompilationUnit) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_IndexBuilderTestCase_CompilationUnit_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CompileTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_CompileTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CompileTestCase_Error) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_CompileTestCase_Error_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CompileTestCase_Variables) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_CompileTestCase_Variables_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CompileTestCase_Variables_DerivedRole) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_CompileTestCase_Variables_DerivedRole_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CelTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_CelTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *SchemaTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_SchemaTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ValidationErrContainer) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ValidationErrContainer_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *AttrWrapper) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_AttrWrapper_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *QueryPlannerTestSuite) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_QueryPlannerTestSuite_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *QueryPlannerTestSuite_Test) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_QueryPlannerTestSuite_Test_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *VerifyTestFixtureGetTestsTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_VerifyTestFixtureGetTestsTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *QueryPlannerFilterTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_QueryPlannerFilterTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *VerifyTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_VerifyTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ProtoYamlTestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ProtoYamlTestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ProtoYamlTestCase_Want) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_private_v1_ProtoYamlTestCase_Want_hashpb_sum(m, hasher, ignore)
	}
}
