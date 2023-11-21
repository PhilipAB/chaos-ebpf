package errors

import (
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

/**************************************************************************************************************
 * General gRPC errors
 *
 * The following functions are applicable for RPC responses
 **************************************************************************************************************/

// generic function which returns a standard gRPC status error
// @errorMsg: The error message to return
// @details: A proto message
// @c: The kind of the returned error
func SimpleGrpcError[T proto.Message](errorMsg string, details T, c codes.Code) error {
	err := status.Newf(
		c,
		"parameter filter is missing",
	)
	err, wde := err.WithDetails(details)
	if wde != nil {
		return wde
	}
	return err.Err()
}

// generic function which represents an internal error as gRPC status error
// @errorMsg: Formated error message - should contain %v
// @details: A proto message
// @internalErr: an internal error
func InternalGrpcError[T proto.Message](errorMsg string, details T, internalErr error) error {
	err := status.Newf(
		codes.Internal,
		errorMsg,
		internalErr,
	)
	err, wde := err.WithDetails(details)
	if wde != nil {
		return wde
	}
	return err.Err()
}

// this function creates an error which occurs if the attachment of an eBPF program fails
// @details: A proto message
// @mode: either "attach" or "detach"
// @ns: network namespace
// @iFaceName: network interface name
// @internalErr: the internal error, describing, why the attachment failed
func EbpfAttachDetachGrpcError[T proto.Message](details T, mode string, ns string, iFaceName string, internalErr error) error {
	err := status.Newf(
		codes.Internal,
		"could not %s program for interface %s in namespace %s: %v",
		mode,
		iFaceName,
		ns,
		internalErr,
	)
	err, wde := err.WithDetails(details)
	if wde != nil {
		return wde
	}
	return err.Err()
}

// error message that describes which attachments/detachments to network interfaces failed
// @details: A proto message
// @mode: either "attach" or "detach"
// @ns: network namespace
// @iFaceName: network interface name
func AttachDetachAllGrpcError[T proto.Message](details T, mode string, ns string, iFaceNames string) error {
	err := status.Newf(
		codes.Internal,
		"could not %s program(s) for interface(s) %s in namespace %s",
		mode,
		iFaceNames,
		ns,
	)
	err, wde := err.WithDetails(details)
	if wde != nil {
		return wde
	}
	return err.Err()
}
