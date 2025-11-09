# Requirements Document

## Introduction

This feature adds JWT authentication support to the Swagger UI interface, enabling developers to authenticate and test protected API endpoints directly from the browser-based documentation. Currently, the Swagger UI lacks an "Authorize" button, preventing users from testing authenticated endpoints like `/whoami` without external tools like curl or Postman.

## Glossary

- **Swagger UI**: Browser-based interactive API documentation interface auto-generated from OpenAPI specifications
- **OpenAPI Service**: The poem-openapi service that generates OpenAPI 3.0 specifications and serves the Swagger UI
- **Security Scheme**: OpenAPI specification component that defines authentication methods (e.g., Bearer token, API key)
- **Bearer Token**: JWT access token passed in the Authorization header with "Bearer " prefix
- **Protected Endpoint**: API endpoint that requires valid JWT authentication to access

## Requirements

### Requirement 1

**User Story:** As a developer, I want to see an "Authorize" button in the Swagger UI, so that I can authenticate before testing protected endpoints

#### Acceptance Criteria

1. WHEN THE **Swagger UI** loads, THE **Swagger UI** SHALL display an "Authorize" button in the top-right corner
2. THE **OpenAPI Service** SHALL define a Bearer token security scheme in the OpenAPI specification
3. THE **Security Scheme** SHALL specify "Bearer" as the scheme type with JWT format
4. THE **OpenAPI Service** SHALL name the security scheme "BearerAuth" for consistent reference

### Requirement 2

**User Story:** As a developer, I want to enter my JWT token in the Swagger UI, so that subsequent API requests include authentication

#### Acceptance Criteria

1. WHEN a user clicks the "Authorize" button, THE **Swagger UI** SHALL display a modal dialog for entering credentials
2. THE **Modal Dialog** SHALL provide a text input field labeled "Value" for entering the JWT token
3. WHEN a user enters a token and clicks "Authorize", THE **Swagger UI** SHALL store the token for subsequent requests
4. WHEN a user clicks "Logout", THE **Swagger UI** SHALL clear the stored token
5. THE **Swagger UI** SHALL automatically prepend "Bearer " to the token value in the Authorization header

### Requirement 3

**User Story:** As a developer, I want the `/whoami` endpoint to show a lock icon in Swagger UI, so that I know it requires authentication

#### Acceptance Criteria

1. THE **/whoami Endpoint** SHALL be annotated with the security scheme in its OpenAPI definition
2. WHEN THE **Swagger UI** displays the `/whoami` endpoint, THE **Swagger UI** SHALL show a lock icon next to the endpoint
3. WHEN a user has not authenticated, THE **Lock Icon** SHALL appear unlocked or grayed out
4. WHEN a user has authenticated, THE **Lock Icon** SHALL appear locked or highlighted
5. THE **/login Endpoint** SHALL NOT be annotated with the security scheme and SHALL remain publicly accessible
6. THE **/refresh Endpoint** SHALL NOT be annotated with the security scheme and SHALL remain publicly accessible

### Requirement 4

**User Story:** As a developer, I want to test the `/whoami` endpoint from Swagger UI after authenticating, so that I can verify my JWT token works

#### Acceptance Criteria

1. WHEN a user authenticates with a valid JWT, THE **Swagger UI** SHALL include the Authorization header in requests to the `/whoami` endpoint
2. WHEN a user executes the `/whoami` endpoint with valid authentication, THE **/whoami Endpoint** SHALL return a 200 status with user information
3. WHEN a user executes the `/whoami` endpoint without authentication, THE **/whoami Endpoint** SHALL return a 401 status with an error message
4. THE **Swagger UI** SHALL display the full request including headers for debugging purposes
5. THE **/login Endpoint** SHALL function without requiring authentication in the Swagger UI
6. THE **/refresh Endpoint** SHALL function without requiring authentication in the Swagger UI

### Requirement 5

**User Story:** As a developer, I want to obtain a JWT token from the `/login` endpoint in Swagger UI, so that I can immediately test protected endpoints without external tools

#### Acceptance Criteria

1. THE **/login Endpoint** SHALL remain publicly accessible without authentication requirements
2. WHEN a user executes the `/login` endpoint with valid credentials, THE **/login Endpoint** SHALL return a JWT access token in the response
3. THE **User** SHALL be able to copy the access token from the response body
4. THE **User** SHALL be able to paste the copied token into the "Authorize" dialog
5. THE **Swagger UI** SHALL allow testing the complete authentication flow (login → authorize → test protected endpoint) without leaving the browser
