---
inclusion: manual
---

# Spec Development - Task Organization Rules

## Core Principle: Incremental Testing

When creating task lists, organize work into **phases** where each phase delivers a testable, working feature. Never save all testing for the end.

## Phase Ordering Rules (MANDATORY)

**Order phases by dependency:**

1. **Phase 0: Critical Security/Prerequisites** (if needed)
2. **Phase 1-N: Build from foundation up**
   - Infrastructure before consumers
   - Store layer before service layer  
   - Service layer before API layer
   - Shared utilities before specific implementations
3. **Final Phase: Integration + Documentation**

## Anti-Patterns to Avoid

❌ **Don't order phases backwards**
```
Phase 1: API endpoints
Phase 2: Service layer
Phase 3: Database
```

✅ **Do order phases by dependency**
```
Phase 1: Database
Phase 2: Service layer
Phase 3: API endpoints
```

❌ **Don't add automated test code tasks unless user requests them**
```
Phase 1: Implement feature
Phase 2: Write unit tests  ← Don't add this automatically
```

✅ **Do verify implementation works, but don't write test code**
```
Phase 1: Implement feature
  - Write the code
  - Verify it compiles
  - Run it to confirm it works
  - (No automated test code unless user requests)
```

## Decision Tree for Phase Ordering

```
START
  ↓
Critical security/prerequisites needed?
  YES → Phase 0
  NO → Continue
  ↓
Shared infrastructure needed?
  YES → Phase N: Infrastructure
  ↓
Data layer changes needed?
  YES → Phase N+1: Store Layer
  ↓
Business logic needed?
  YES → Phase N+2: Service Layer
  ↓
API endpoints needed?
  YES → Phase N+3: API Layer
  ↓
Phase N+4: Integration
Phase N+5: Documentation
  ↓
END
```

## Key Principles

1. Each phase should deliver a **working, verified feature**. After completing a phase, you must verify that the feature works (compile, run, manual testing) before moving to the next phase.

2. **Automated tests are user-driven**: Do NOT add automated test tasks (unit tests, integration tests) to the task list unless explicitly requested by the user. However, you MUST still verify your implementation works by:
   - Ensuring code compiles without errors
   - Running the application to verify functionality
   - Manually testing the feature works as expected
   - Checking for regressions in existing functionality
