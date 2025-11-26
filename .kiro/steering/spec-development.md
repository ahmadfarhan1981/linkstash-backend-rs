---
inclusion: manual
---

# Spec Development - Task List Generation Rules

## CRITICAL: When Creating tasks.md Files

You MUST structure task lists using incremental testing phases. Each phase MUST be independently testable.

## Required Structure

```markdown
# Implementation Plan - Incremental Testing Approach

**Note:** [Dependencies and context]
**Strategy:** Tasks organized for testing after each feature, not at end.

---

## Phase N: [Feature Name]

### Task N.1: [Implementation]
- [ ] Concrete action
- [ ] _Requirements: X.Y_
- [ ] _Testable: Verification criteria_

### Task N.2: Test [Feature]
- [ ]* Write test: Specific scenario
- [ ]* **✅ PHASE N COMPLETE - [Feature] is working**

---

## Testing Checkpoints
[Verification steps]

## Estimated Timeline
[Per-phase estimates]
```

## Phase Ordering Rules (MANDATORY)

Apply in this order:

1. **Phase 0: Critical Security/Prerequisites** - ALWAYS FIRST if needed
2. **Phase 1-N: Dependencies → Features**
   - Infrastructure before consumers
   - Store layer before service layer
   - Service layer before API layer
   - Shared utilities before specific implementations
3. **Final Phase: Integration + Documentation**

## Task Granularity Rules

- Each task: 1-4 hours of work
- Must have `_Testable:` line stating what can be verified
- Must reference `_Requirements:` from requirements.md
- Testing tasks marked with `[ ]*` (asterisk)
- Each phase ends with `**✅ PHASE N COMPLETE - [Feature] is working**`

## Phase Content Rules

### Implementation Tasks
```markdown
### Task N.1: [Action Verb] [Component/Feature]
- [ ] Concrete implementation step (not vague)
- [ ] Another concrete step
- [ ] _Requirements: X.Y, Z.W_
- [ ] _Testable: [Specific verification criteria]_
```

RULES:
- Use action verbs: Create, Implement, Add, Update, Call, Check
- Be specific: "Add system_config_store field to AuthService" not "Update AuthService"
- Include file paths when creating new files
- List concrete steps, not outcomes
- ALWAYS include `_Requirements:` line
- ALWAYS include `_Testable:` line

### Testing Tasks
```markdown
### Task N.X: Test [Feature Name]
- [ ]* Write test: [Specific scenario with expected behavior]
- [ ]* Write test: [Error case with expected error]
- [ ]* Write test: [Edge case]
- [ ]* Write test: [Security/authorization case]
- [ ]* Write test: [Integration scenario]
- [ ]* **✅ PHASE N COMPLETE - [Feature] is working**
```

RULES:
- Mark with `[ ]*` (asterisk after checkbox)
- Each test describes scenario AND expected outcome
- Cover: happy path, errors, edges, security, integration
- MUST end with completion marker
- Completion marker format: `**✅ PHASE N COMPLETE - [Feature] is working**`

### Required End Sections

ALWAYS include these sections at end of tasks.md:

```markdown
## Testing Checkpoints

After each phase, verify:
- [ ] All tests in that phase pass
- [ ] No regressions in previous phases
- [ ] Code compiles without warnings
- [ ] [Context-specific verification]

## Estimated Timeline

- Phase 0: X-Y hours [if exists]
- Phase 1: X-Y hours
- Phase N: X-Y hours

**Total: X-Y hours**
```

## Anti-Patterns (DO NOT DO)

### ❌ WRONG: All tests at end
```markdown
- [ ] Implement feature A
- [ ] Implement feature B  
- [ ] Test everything
```

### ❌ WRONG: No phases
```markdown
- [ ] Random task 1
- [ ] Random task 2
```

### ❌ WRONG: Vague tasks
```markdown
- [ ] Make it work
- [ ] Fix bugs
```

### ❌ WRONG: Wrong dependency order
```markdown
Phase 1: API endpoints
Phase 2: Service layer
Phase 3: Database
```

### ❌ WRONG: Missing required fields
```markdown
### Task 1.1: Do something
- [ ] Step 1
- [ ] Step 2
```
(Missing `_Requirements:` and `_Testable:`)

## Correct Example

```markdown
## Phase 2: Token Service

### Task 2.1: Create TokenService struct
- [ ] Create src/services/token_service.rs
- [ ] Add jwt_secret and refresh_secret fields
- [ ] Implement new(jwt_secret, refresh_secret) constructor
- [ ] Export from src/services/mod.rs
- [ ] _Requirements: 3.1, 3.2_
- [ ] _Testable: TokenService can be instantiated with secrets_

### Task 2.2: Implement generate_jwt method
- [ ] Accept user_id, is_owner, is_system_admin, is_role_admin, app_roles parameters
- [ ] Create Claims struct with exp=15min, iat=now, jti=uuid
- [ ] Use jsonwebtoken::encode with HS256 algorithm
- [ ] Return (jwt_string, jti)
- [ ] _Requirements: 3.3, 3.4_
- [ ] _Testable: JWT can be generated and contains correct claims_

### Task 2.3: Test token generation
- [ ]* Write test: generate_jwt creates valid JWT with correct claims
- [ ]* Write test: JWT expires in 15 minutes
- [ ]* Write test: JWT includes all admin role flags
- [ ]* Write test: JWT includes app_roles array
- [ ]* Write test: jti is unique per token
- [ ]* **✅ PHASE 2 COMPLETE - Token generation is working**

---
```

## Decision Tree for Phase Ordering

```
START
  ↓
Is there a critical security fix needed?
  YES → Phase 0: Security Fix
  NO → Continue
  ↓
Does feature need shared infrastructure?
  YES → Phase 1: Infrastructure
  NO → Continue
  ↓
Does feature need data layer changes?
  YES → Phase N: Store Layer
  NO → Continue
  ↓
Does feature need business logic?
  YES → Phase N+1: Service Layer
  NO → Continue
  ↓
Does feature need API endpoints?
  YES → Phase N+2: API Layer
  NO → Continue
  ↓
Phase N+3: Integration
Phase N+4: Documentation
  ↓
END
```

## Template (Copy This)

```markdown
# Implementation Plan - Incremental Testing Approach

**Note:** [What this implements + dependencies]
**Strategy:** Test after each feature, not at end.

---

## Phase 0: [Critical/Prerequisites - if needed]

### Task 0.1: [Action] [Component]
- [ ] Concrete step
- [ ] _Requirements: X.Y_
- [ ] _Testable: [Verification]_

### Task 0.2: Test [Feature]
- [ ]* Write test: [Scenario + expected]
- [ ]* **✅ PHASE 0 COMPLETE - [Feature] is working**

---

## Phase 1: [Infrastructure/Foundation]

### Task 1.1: [Action] [Component]
- [ ] Concrete step
- [ ] _Requirements: X.Y_
- [ ] _Testable: [Verification]_

### Task 1.2: Test [Feature]
- [ ]* Write test: [Scenario + expected]
- [ ]* **✅ PHASE 1 COMPLETE - [Feature] is working**

---

[Repeat for each phase]

---

## Testing Checkpoints

After each phase, verify:
- [ ] All tests in that phase pass
- [ ] No regressions in previous phases
- [ ] Code compiles without warnings

## Estimated Timeline

- Phase 0: X-Y hours
- Phase 1: X-Y hours

**Total: X-Y hours**
```
