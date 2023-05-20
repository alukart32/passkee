/*
Package v1 provides services for gRPC API v1 routes.

Interaction with the client is carried out on the following domains:

 1. processing client sessions
 2. user authentication
 3. password pair, credit card, bin objects

Before calling the methods of grpc services, the user is authenticated,
the basic auth strategy is applied by default.

Methods that do not require authentication:

  - authpb.Auth_LogOn,
  - authpb.Session_Handshake,
  - authpb.Session_Terminate

The gRPC server authentication is defined in the grpc grpcauth package by the BasicAuth method.

gRPC method Call Execution Workflow:

 0. authentication - setting userID, SessionID
 1. getting a session based on the request context
 2. creating a session message encryptor
 3. domain logic
 4. return of the execution result
*/
package v1
