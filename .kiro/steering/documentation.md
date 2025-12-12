---
inclusion: always
---

# Documentation Protocol

## When to Document

Document functionality when:
- Developers need to extend or modify existing code
- System administrators need to configure or run the system
- The implementation involves non-obvious patterns or decisions

## What NOT to Document

- **API endpoints** - Swagger UI provides sufficient documentation
- **End-user functionality** - Client applications handle UX documentation
- **Self-explanatory code** - Let the code speak for itself

## Documentation Location

- **`docs/` directory** - All developer and admin documentation
- Use descriptive filenames: `adding-secrets.md`, `extending-auth.md`, etc.
- Keep docs focused and concise

## Documentation Audience

1. **Developers** - Extending or modifying the system
   - Architecture decisions
   - Extension points
   - Code patterns and conventions
   
2. **Administrators** - Running and configuring the system
   - Deployment procedures
   - Configuration options
   - Troubleshooting guides

3. **End Users** - NOT our responsibility
   - Swagger UI covers API usage
   - Client applications handle user experience

## Documentation Format

- Use Markdown
- Include code examples where helpful
- Keep it practical and actionable
- Update docs when changing related functionality