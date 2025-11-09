# Implementation Plan

- [x] 1. Add BearerAuth security scheme to AuthApi




  - Define `BearerAuth` struct with `SecurityScheme` derive macro in `src/api/auth.rs`
  - Configure security scheme attributes: `ty = "http"`, `scheme = "bearer"`, `bearer_format = "JWT"`
  - Add user-friendly description for Swagger UI
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 2. Update whoami endpoint to use BearerAuth





  - Replace `headers: &HeaderMap` parameter with `auth: BearerAuth` in whoami function signature
  - Remove manual Authorization header extraction logic
  - Access token directly via `auth.0` instead of parsing from headers
  - Keep JWT validation logic using `TokenService::validate_jwt()`
  - _Requirements: 3.1, 4.1, 4.2, 4.3_

- [x] 3. Update whoami endpoint tests





  - Modify tests to construct `BearerAuth` directly instead of creating `HeaderMap`
  - Update test helper functions to use new authentication pattern
  - Remove or simplify tests for missing/malformed headers (poem handles automatically)
  - Verify tests for valid JWT, invalid JWT, and expired JWT still pass
  - _Requirements: 4.2, 4.3_

- [ ]* 4. Perform manual testing in Swagger UI
  - Start server and navigate to http://localhost:3000/swagger
  - Verify "Authorize" button appears in top-right corner
  - Verify lock icon appears on `/whoami` endpoint only
  - Test login flow: execute `/login`, copy token, paste into "Authorize" modal
  - Verify `/whoami` returns 200 with valid token
  - Verify `/whoami` returns 401 without token
  - Verify `/login` and `/refresh` remain publicly accessible
  - _Requirements: 1.1, 2.1, 2.2, 2.3, 2.4, 2.5, 3.2, 3.3, 3.4, 4.4, 4.5, 4.6, 5.1, 5.2, 5.3, 5.4, 5.5_
