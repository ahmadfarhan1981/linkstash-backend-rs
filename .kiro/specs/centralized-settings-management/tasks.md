# Implementation Plan

- [x] 1. Set up core configuration infrastructure
  - Create modular settings management system with focused modules
  - Define `ConfigSource`, `ConfigSpec`, and `ConfigValue` types in `config_spec.rs`
  - Implement error types for settings management in `errors.rs`
  - Refactor monolithic file into maintainable modules
  - _Requirements: 3.1, 4.5, 5.1_

- [x] 2. Implement BootstrapSettings layer
  - Create `BootstrapSettings` struct in `bootstrap_settings.rs` for infrastructure configuration
  - Implement environment variable loading for database URL, host, port
  - Add validation for required bootstrap settings
  - Include comprehensive test suite with environment variable isolation
  - _Requirements: 1.4, 1.5, 7.1, 7.2, 7.4, 7.5_

- [ ]* 2.1 Write property test for bootstrap settings validation
  - **Property 2: Layer-specific initialization validation**
  - **Validates: Requirements 1.4, 1.5**

- [ ]* 2.2 Write property test for server configuration validation
  - **Property 9: Range validation enforcement**
  - **Validates: Requirements 7.4, 8.4**

- [x] 3. Implement configuration loading with source tracking
  - Create `load_setting_with_source()` method in `config_spec.rs` that returns `ConfigValue`
  - Implement priority logic: env override → persistent source → default
  - Add source tracking for environment variables, database, and defaults
  - Include validation and error handling with descriptive messages
  - _Requirements: 3.2, 3.3, 3.5, 9.4_

- [ ]* 3.1 Write property test for configuration source priority
  - **Property 4: Configuration source priority**
  - **Validates: Requirements 3.2, 3.3**

- [ ]* 3.2 Write property test for validation consistency across sources
  - **Property 5: Validation rule consistency**
  - **Validates: Requirements 5.3, 5.4**

- [x] 4. Create database migration for system_settings table
  - Add migration to create `system_settings` table with key, value, description, category
  - Include sample data for rate limiting and audit retention settings
  - _Requirements: Database schema support_

- [x] 5. Implement ApplicationSettings with caching
  - Create `ApplicationSettings` struct in `application_settings.rs` with `Arc<RwLock<T>>` cached values
  - Implement initialization that loads and caches all settings
  - Add typed getter methods for JWT expiration, refresh token expiration
  - Include runtime update support and comprehensive test suite
  - _Requirements: 1.1, 2.1, 2.4, 8.1, 8.2_

- [x] 5.3 Refactor settings management into modular architecture
  - Split monolithic 1700+ line file into focused modules
  - Improve maintainability and testability
  - Preserve all existing functionality and tests
  - Create clean module boundaries and responsibilities
  - _Requirements: Code organization and maintainability_

- [ ]* 5.1 Write property test for typed getter consistency
  - **Property 1: Typed getter interface consistency**
  - **Validates: Requirements 1.1, 1.3, 2.1, 2.4**

- [ ]* 5.2 Write property test for type parsing correctness
  - **Property 3: Type parsing correctness**
  - **Validates: Requirements 2.2, 2.3**

- [x] 6. Implement type parsing and validation





  - Add parsing functions for durations, booleans, integers, strings
  - Implement custom validation support in ConfigSpec
  - Add range validation for ports and durations
  - _Requirements: 2.2, 2.3, 7.4, 8.3, 8.4_

- [ ]* 6.1 Write property test for duration parsing
  - **Property 10: Format support completeness**
  - **Validates: Requirements 7.5, 8.3**

- [ ]* 6.2 Write property test for range validation
  - **Property 9: Range validation enforcement**
  - **Validates: Requirements 7.4, 8.4**

- [x] 7. Implement runtime configuration updates




  - Add `update_setting()` method with database write + cache update
  - Implement `get_setting_info()` for source and mutability information
  - Add validation to prevent updates to environment-overridden settings
  - _Requirements: 9.1, 9.2, 9.3, 9.5_

- [ ]* 7.1 Write property test for runtime update consistency
  - **Property 12: Runtime update consistency**
  - **Validates: Requirements 9.1, 9.2**

- [ ]* 7.2 Write property test for environment variable immutability
  - **Property 13: Environment variable immutability**
  - **Validates: Requirements 9.3**

- [x] 8. Implement SettingsManager coordination layer





  - Create main `SettingsManager` struct with lazy initialization
  - Implement `init_full()` and `init_bootstrap_only()` methods
  - Add convenience methods that delegate to appropriate layers
  - _Requirements: 1.2, 5.4, 5.5_

- [ ]* 8.1 Write property test for default value handling
  - **Property 8: Layer-appropriate default value handling**
  - **Validates: Requirements 7.3, 8.5**

- [ ] 9. Implement error handling and logging
  - Add comprehensive error messages with setting names and expected formats
  - Implement initialization logging with setting counts
  - Add Debug/Display traits that show actual values (not redacted)
  - _Requirements: 2.5, 4.3, 4.4, 6.1, 6.3, 6.4, 6.5_

- [ ]* 9.1 Write property test for error message quality
  - **Property 6: Error message informativeness**
  - **Validates: Requirements 2.5, 6.2, 6.5**

- [ ]* 9.2 Write property test for debug transparency
  - **Property 7: Debug transparency**
  - **Validates: Requirements 4.3, 4.4**

- [ ]* 9.3 Write property test for initialization logging
  - **Property 11: Initialization logging consistency**
  - **Validates: Requirements 6.1, 6.3, 6.4**

- [ ] 10. Integrate with AppData pattern
  - Add `SettingsManager` to `AppData` struct
  - Update `AppData::init()` to initialize SettingsManager
  - Update coordinators to access settings through AppData
  - _Requirements: 5.5_

- [ ] 11. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Update existing hardcoded configuration usage
  - Replace hardcoded JWT expiration with SettingsManager access
  - Replace hardcoded server host/port with BootstrapSettings
  - Update any other scattered configuration access
  - _Requirements: Migration from existing code_

- [ ]* 12.1 Write integration tests for coordinator usage
  - Test that coordinators can access settings through AppData
  - Test that settings changes are reflected in coordinator behavior
  - _Requirements: Integration testing_

- [ ] 13. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.