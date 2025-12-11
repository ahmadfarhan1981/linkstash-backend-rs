---
inclusion: manual
---

# Spec Development - Task Organization Rules

## Core Principle: Incremental Feature Development

Build features **incrementally** where each task delivers a working, testable piece of functionality. Prioritize getting **user-facing features** working end-to-end quickly, then enhance them. Never save all testing for the end.

## Incremental Development Strategy

**Build features in progressive iterations:**

1. **Start with minimal viable user-facing functionality** - Get something users can interact with (API endpoint, CLI command) working end-to-end quickly, even if internal validation/logic is basic
2. **Add complexity incrementally** - Enhance internal components (validators, stores) in subsequent tasks
3. **Keep the system working** - Each task should leave the application in a runnable state
4. **Verify as you go** - Verify each task's output works before moving forward

**Key distinction:** "Working early" means **user-facing features** (API endpoints, CLI commands), not internal components (validators, stores, coordinators, providers). Internal components can be built more completely before integration if it reduces rework.

### Example: Password Change Feature with Multiple Validation Types

❌ **Don't build everything before delivering user-facing feature:**
```
Task 1: Implement complete validator (length + common passwords + HIBP + username check)
Task 2: Implement all stores (CommonPasswordStore + HibpCacheStore)
Task 3: Implement coordinator and provider layers
Task 4: Implement API layer
Task 5: Test everything
```

✅ **Do deliver user-facing feature early, then enhance:**
```
Task 1: Database migrations (all tables - cheap and stable)
Task 2: Database entities
Task 3: Implement basic validator (length check only)
Task 4: Implement password change coordinator and providers using basic validator
Task 5: Implement password change API endpoint (users can change passwords!)
Task 6: Add CommonPasswordStore
Task 7: Enhance validator to check common passwords
Task 8: Add HibpCacheStore
Task 9: Enhance validator to check HIBP
```

**Benefits:**
- **User-facing feature (password change endpoint) works by Task 5** - even with basic validation
- Each enhancement is testable through the user-facing feature
- Early feedback on the complete flow (API → Coordinator → Provider → Store → Database)
- Acceptable rework trade-off for faster user value

**Key insight:** The validator is an internal component. It's okay to build it incrementally, but the priority is getting the **user-facing password change endpoint** working quickly.

## Task Ordering Guidelines

**Prioritize user-facing features, be pragmatic with internal components:**

1. **User-facing features first (vertical slices):**
   - Get API endpoints or CLI commands working end-to-end quickly
   - Use minimal internal logic initially (basic validation, simple queries)
   - Example: Password change endpoint with length-only validation
   - **Goal:** Users can interact with the feature early

2. **Some components should be built completely upfront:**
   
   **Build complete structure upfront:**
   - Database schemas - Create all anticipated tables/columns in one migration
   - Struct definitions - Define final shape with all fields, populate incrementally
   - Error enums - Define all error variants, even if some aren't returned yet
   - Configuration structs - Define all config fields, use defaults for unimplemented features
   
   **Build incrementally:**
   - Validation logic - Easy to add rules without changing signatures
   - Business logic - Can enhance without breaking existing code
   - Store/Coordinator/Provider methods - Can add new methods without affecting existing ones
   - API endpoints - Adding new endpoints doesn't affect existing ones
   
   **Rationale:** Database migrations and struct changes ripple through multiple layers. Cheaper to define the complete structure once and use it incrementally.

3. **Decision framework:**
   - **High priority:** User-facing feature working early (API endpoint, CLI command)
   - **Medium priority:** Complete structure for schemas/types/errors upfront
   - **Low priority:** Full implementation of all logic before any use

**Example ordering:**
```
✅ Good: Database/types/errors → Minimal logic → Coordinator/Provider → API endpoint (user feature!) → Enhance logic
❌ Bad: Complete all components before delivering any user-facing feature
```

## Task Granularity

**Each task should produce a verifiable work product:**

- A store implementation can be a task (verifiable via manual testing or existing tests)
- A coordinator method can be a task (verifiable via coordinator layer)
- A provider method can be a task (verifiable via provider layer)
- An API endpoint can be a task (verifiable via HTTP calls)
- An enhancement to existing code can be a task (verifiable by checking new behavior)

**Each task should leave the system in a working state:**
- Code compiles without errors
- Application runs without crashes
- Existing functionality still works
- New functionality is verifiable (even if not complete)

## Anti-Patterns to Avoid

❌ **Don't build everything before testing:**
```
Task 1-10: Implement all components
Task 11: Test everything
```

❌ **Don't order tasks backwards (consumers before dependencies):**
```
Task 1: API endpoint that calls non-existent coordinator
Task 2: Coordinator that calls non-existent provider
Task 3: Provider that calls non-existent store
Task 3: Store implementation
```

❌ **Don't add automated test code tasks:**
```
Task 1: Implement feature
Task 2: Write unit tests  ← Don't add this automatically
```

## Testing During Implementation

DO NOT add these tasks:
- "Write unit tests for X"  
- "Add integration tests"
- "Create test fixtures"

DO verify your implementation:
- Run `cargo build` - ensure compilation
- Run `cargo test --lib` - ensure existing tests pass
- For API endpoints: Test via curl/Swagger after implementation
- For stores/coordinators/providers: Verify code compiles and existing tests pass

Exception: If spec design includes property-based testing requirements, implement those tests.

User will request strategic test coverage after seeing the full implementation.

## Task List Format (MANDATORY)

**Use this exact format for all task lists:**

```markdown
# Implementation Plan

- [ ] 1. Task description (e.g., "Implement basic password validator with length check")
  - Implementation details as bullets
  - _Requirements: X.Y, Z.W_

- [ ] 2. Next task description
  - Details
  - _Requirements: A.B_
```

**Critical Rules:**
1. **Tasks are top-level checkboxes** (e.g., `- [ ] 1. Task description`)
2. **Details are bullets without checkboxes** (indented under tasks)
3. Use the `taskStatus` tool with the EXACT task text (e.g., "1. Task description")
4. Each task should reference relevant requirements

## Key Principles

1. **Each task delivers working functionality** - After completing a task, verify it works (compile, run, test) before moving forward.

2. **Incremental complexity** - Start simple, add features progressively. A basic working feature is better than a complete non-working feature.

3. **Pragmatic infrastructure** - Build complete structure upfront for schemas/types/errors (they ripple through layers when changed). Build logic incrementally (easy to enhance without breaking existing code).

4. **Automated tests are user-driven** - Do NOT add automated test tasks (unit tests, integration tests) unless explicitly requested. See "Testing During Implementation" section for verification requirements.

5. **Explicit modifications** - When a task requires modifying previous work, state it clearly in the task description (e.g., "Update validator signature to accept username parameter")
