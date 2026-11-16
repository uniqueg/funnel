package auth

import (
	"context"

	"github.com/calypr/funnel/api/tes"
	"github.com/calypr/funnel/internal/events"
	"github.com/calypr/funnel/internal/identity"
	"github.com/calypr/funnel/internal/server/taskservice"
	"github.com/calypr/funnel/internal/tesrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// workerCalls is implemented by a task service that limits event writes
// and execution claims to its own components (the TES AuthZ hook).
type workerCalls interface {
	AuthorizeWorkerCall(ctx context.Context) error
}

// EventWriteInterceptor checks that event writes target accessible tasks.
// With the TES AuthZ hook, event writes and execution claims are limited
// to the callers the hook exempts (Basic-auth administrators).
func EventWriteInterceptor(tasks tesrpc.TaskServiceServer) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if guard, ok := tasks.(workerCalls); ok && (info.FullMethod == events.EventService_WriteEvent_FullMethodName || info.FullMethod == events.EventService_ClaimExecution_FullMethodName) {
			if err := guard.AuthorizeWorkerCall(ctx); err != nil {
				return nil, err
			}
		}
		if info.FullMethod != events.EventService_WriteEvent_FullMethodName {
			return handler(ctx, req)
		}
		event, ok := req.(*events.Event)
		if !ok || event == nil || event.Id == "" {
			return nil, status.Error(codes.InvalidArgument, "task event and task id are required")
		}
		if event.Type == events.Type_TASK_CREATED {
			user := identity.GetUser(ctx)
			if !user.IsAdmin && !user.IsPublic {
				return nil, status.Error(codes.PermissionDenied, "create tasks through the TES task API")
			}
		} else {
			// A worker path: TaskAccess decides, not the TES AuthZ hook.
			internal := context.WithValue(ctx, taskservice.InternalCallKey, true)
			_, err := tasks.GetTask(internal, &tes.GetTaskRequest{Id: event.Id, View: tes.View_MINIMAL.String()})
			if err != nil {
				return nil, err
			}
		}
		return handler(ctx, req)
	}
}
