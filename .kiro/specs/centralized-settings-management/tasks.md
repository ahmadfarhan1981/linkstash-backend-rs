# Implementation Plan

- [ ] 1. Set up core configuration infrastructure
  - Create `src/config/settings_manager.rs` module
  - Define `ConfigSource`, `ConfigSpec`, and `ConfigValue` types
  - Implement basic error types for settings management
  - _Requirements: 3.1, 4.5, 5.1_

- [ ] 2. Implement BootstrapSettings layer
  - Create `BootstrapSettings` struct for infrastructure configuration
  - Implement environment variable loading for database URL, host, port
  - Add validation for required bootstrap settings
  - _Requirements: 1.4, 1.5, 7.1, 7.2, 7.4, 7.5_

- [ ]* 2.1 Write property test for bootstrap settings validation
  - **Property 2: Layer-specific initialization validation**
  - **Validates: Requirements 1.4, 1.5**

- [ ]* 2.2 Write property test for server configuration validation
  - **Property 9: Range validation enforcement**
  - **Validates: Requirements 7.4, 8.4**

- [ ] 3. Implement configuration loading with source tracking
  - Create `load_setting_with_source()` method that returns `ConfigValue`
  - Implement priority logic: env override → persistent source → default
  - Add source tracking for environment variables, database, and defaults
  - _Requirements: 3.2, 3.3, 3.5, 9.4_

- [ ]* 3.1 Write property test for configuration source priority
  - **Property 4: Configuration source priority**
  - **Validates: Requirements 3.2, 3.3**

- [ ]* 3.2 Write property test for validation consistency across sources
  - **Property 5: Validation rule consistency**
  - **Validates: Requirements 5.3, 5.4**

- [ ] 4. Implement ApplicationSettings with caching
  - Create `ApplicationSettings` struct with `Arc<RwLock<T>>` cached values
  - Implement initialization that loads and caches all settings
  - Add typed getter methods for JWT expiration, refresh token expiration
  - _Requirements: 1.1, 2.1, 2.4, 8.1, 8.2_

- [ ]* 4.1 Write property test for typed getter consistency
  - **Property 1: Typed getter interface consistency**
  - **Validates: Requirements 1.1, 1.3, 2.1, 2.4**

- [ ]* 4.2 Write property test for type parsing correctness
  - **Property 3: Type parsing correctness**
  - **Validates: Requirements 2.2, 2.3**

- [ ] 5. Implement type parsing and validation
  - Add parsing functions for durations, booleans, integers, strings
  - Implement custom validation support in ConfigSpec
  - Add range validation for ports and durations
  - _Requirements: 2.2, 2.3, 7.4, 8.3, 8.4_

- [ ]* 5.1 Write property test for duration parsing
  - **Property 10: Format support completeness**
  - **Validates: Requirements 7.5, 8.3**

- [ ]* 5.2 Write property test for range validation
  - **Property 9: Range validation enforcement**
  - **Validates: Requirements 7.4, 8.4**

- [ ] 6. Implement runtime configuration updates
  - Add `update_setting()` method with database write + cache update
  - Implement `get_setting_info()` for source and mutability information
  - Add validation to prevent updates to environment-overridden settings
  - _Requirements: 9.1, 9.2, 9.3, 9.5_

- [ ]* 6.1 Write property test for runtime update consistency
  - **Property 12: Runtime update consistency**
  - **Validates: Requirements 9.1, 9.2**

- [ ]* 6.2 Write property test for environment variable immutability
  - **Property 13: Environment variable immutability**
  - **Validates: Requirements 9.3**

- [ ] 7. Implement SettingsManager coordination layer
  - Create main `SettingsManager` struct with lazy initialization
  - Implement `init_full()` and `init_bootstrap_only()` methods
  - Add convenience methods that delegate to appropriate layers
  - _Requirements: 1.2, 5.4, 5.5_

- [ ]* 7.1 Write property test for default value handling
  - **Property 8: Layer-appropriate default value handling**
  - **Validates: Requirements 7.3, 8.5**

- [ ] 8. Implement error handling and logging
  - Add comprehensive error messages with setting names and expected formats
  - Implement initialization logging with setting counts
  - Add Debug/Display traits that show actual values (not redacted)
  - _Requirements: 2.5, 4.3, 4.4, 6.1, 6.3, 6.4, 6.5_

- [ ]* 8.1 Write property test for error message quality
  - **Property 6: Error message informativeness**
  - **Validates: Requirements 2.5, 6.2, 6.5**

- [ ]* 8.2 Write property test for debug transparency
  - **Property 7: Debug transparency**
  - **Validates: Requirements 4.3, 4.4**

- [ ]* 8.3 Write property test for initialization logging
  - **Property 11: Initialization logging consistency**
  - **Validates: Requirements 6.1, 6.3, 6.4**

- [ ] 9. Integrate with AppData pattern
  - Add `SettingsManager` to `AppData` struct
  - Update `AppData::init()` to initialize SettingsManager
  - Update coordinators to access settings through AppData
  - _Requirements: 5.5_

- [ ] 10. Create database migration for system_settings table
  - Add migration to create `system_settings` table with key, value, description, category
  - Include sample data for rate limiting and audit retention settings
  - _Requirements: Database schema support_

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