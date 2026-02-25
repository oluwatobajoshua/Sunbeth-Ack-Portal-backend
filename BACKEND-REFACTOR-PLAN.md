# Backend Refactor Batches and Features

This document outlines the incremental refactor plan for `sunbeth_doc_backend/index.js`, broken into logical batches. Each batch lists exactly what to move, where to move it, and how to wire it up. After each batch, run tests and verify the app works before proceeding. This mapping ensures you avoid mistakes and always have a working app. Every major feature and code section in `index.js` is mapped below.

---


## Batch 1: Core API Routes (Batches, Documents, Recipients, Acks, Progress, Businesses)
**What to move:**
- All route definitions for:
  - `/api/batches`
  - `/api/documents`
  - `/api/recipients`
  - `/api/acks`
  - `/api/progress`
  - `/api/businesses`
  (Find these in `index.js`, e.g., lines 1000–2000+)

- Also move:
  - `/api/businesses/active` (public list)
  - `/api/businesses/bulk-upload` (CSV/Excel upload)
  - `/api/users/:email/business` (user-business assignment)

**Where to move:**
- For each domain, create:
  - `src/routes/<domain>.js` (e.g., `batches.js`)
  - `src/controllers/<domain>Controller.js` (e.g., `batchesController.js`)

**How to wire up:**
- In each route file, use `express.Router()`, import the controller, and export the router.
- In `index.js`, import and mount each router:
  ```js
  const batchesRouter = require('./src/routes/batches');
  app.use('/api/batches', batchesRouter);
  // Repeat for each domain
  ```
- Remove the original route definitions from `index.js`.

**Features covered:**
- CRUD for batches, documents, recipients, acks, progress, businesses
- User acknowledgement flow
- Data access for frontend dashboards

---


## Batch 2: Admin & Settings APIs
**What to move:**
- All `/api/admin/*` endpoints (tenants, modules, licenses, themes, etc.)
- All settings, feature flags, and tenant management logic

- Also move:
  - `/api/admin/roles`, `/api/admin/settings`, `/api/admin/customization-requests`, `/api/admin/notifications/digest`, `/api/admin/seed/demo`, `/api/admin/tenants/:id/domains`, `/api/admin/tenants/:id/theme`, `/api/admin/themes/:id/clone`, `/api/admin/themes/:id`, `/api/admin/themes`, `/api/admin/tenants/:id/licenses`, `/api/admin/tenants/:id/modules`, `/api/admin/tenants/:id`, `/api/admin/tenants`, `/api/admin/seed/demo`, `/api/admin/notifications/digest`, `/api/admin/customization-requests`, `/api/admin/roles`, `/api/admin/settings`, `/api/admin/theme-assignments`, `/api/admin/tenants/:id/domains`, `/api/admin/tenants/:id/theme`, `/api/admin/themes/:id/clone`, `/api/admin/themes/:id`, `/api/admin/themes`, `/api/admin/tenants/:id/licenses`, `/api/admin/tenants/:id/modules`, `/api/admin/tenants/:id`, `/api/admin/tenants`
  - `/api/flags/effective`, `/api/theme/effective`, `/api/ui/settings`, `/api/diag/db`, `/api/diag/routes`, `/api/health`, `/api/rbac/*` (permissions, role-permissions, user-permissions, effective)
  - All tenant resolver and RBAC logic

**Where to move:**
- `src/routes/admin.js`
- `src/controllers/adminController.js`
- If settings/flags logic is reusable, consider `src/services/settingsService.js`

**How to wire up:**
- In `admin.js`, use `express.Router()`, import controller, export router.
- In `index.js`, import and mount:
  ```js
  const adminRouter = require('./src/routes/admin');
  app.use('/api/admin', adminRouter);
  ```
- Remove original admin/settings routes from `index.js`.

**Features covered:**
- Admin panel (tenants, modules, licenses, themes)
- Settings and feature flag management
- RBAC enforcement for admin APIs

---


## Batch 3: Auth, RBAC, and Middleware
**What to move:**
- All authentication logic (login, session, token validation)
- RBAC logic (role checks, permission matrix)
- All middleware: logging, validation, error handling

- Also move:
  - Request logging middleware
  - Tenant resolver middleware
  - Rate limiting, CORS, helmet, compression, JSON parsing
  - Ajv schema validation
  - SuperAdmin guard
  - Audit logging helper

**Where to move:**
- `src/middleware/auth.js` (authentication)
- `src/middleware/rbac.js` (RBAC)
- `src/middleware/logger.js`, `src/middleware/validate.js`, `src/middleware/errorHandler.js`

**How to wire up:**
- Import and use middleware in route files as needed:
  ```js
  const auth = require('../middleware/auth');
  router.use(auth);
  ```
- Remove original middleware from `index.js`.

**Features covered:**
- User authentication and session
- Role-based access control
- Request logging, validation, error handling

---


## Batch 4: Services (PDF, Email, SharePoint, External Users)
**What to move:**
- PDF generation logic
- Email sending logic (Graph, chunked attachments)
- SharePoint proxy and document upload logic
- External user registration, password reset, MFA logic

- Also move:
  - `/api/certificates/pdf`, `/api/certificates/png`, `/api/certificates/record`, `/api/certificates/verify/:id`
  - `/api/emails/user-completion-pdf`, `/api/emails/admin-completion-pdf`
  - `/api/notification-emails`, `/api/notification-emails` (POST)
  - `/api/files/upload`, `/api/library/save-graph`, `/api/library/list`, `/api/files/:id`, `/api/files/by-path/:relPath`
  - `/api/external-users/*` (all endpoints: search, request-reset, reset-password, mfa, login, google-login, set-password, bulk-upload, invite, resend, invite-batch, resend-batch, patch, delete)
  - `/api/settings/external-support`, `/api/settings/legal-consent`, `/api/settings/reminders`
  - `/api/customization-requests`, `/api/audit-logs`, `/api/audit-logs/seed-demo`

**Where to move:**
- `src/services/pdfService.js`
- `src/services/emailService.js`
- `src/services/sharepointService.js`
- `src/services/externalUserService.js`

**How to wire up:**
- Import services in controllers as needed:
  ```js
  const pdfService = require('../services/pdfService');
  // Use in controller
  ```
- Remove original service logic from `index.js`.

**Features covered:**
- Certificate and email PDF generation
- Email sending (Graph, chunked attachments)
- SharePoint proxy and document upload
- External user registration, password reset, MFA

---


## Batch 5: Database Layer and Utilities
**What to move:**
- All DB adapters and schema logic
- Helpers: logging, formatting, etc.

- Also move:
  - `createDbAdapter`, `exec`, `all`, `one`, `allQuiet`, `persist`, `bootstrapSchema`, `migrateSchema`
  - Utility functions: `createLogger`, `generateRequestId`, `parseJson`, `deepMerge`, `safeParse`, `defaultLight`, `defaultDark`, `mapBatch`, `mapDoc`, etc.
  - Any helper used by multiple modules

**Where to move:**
- `src/db/adapter.js`, `src/db/schema.js`
- `src/utils/logger.js`, `src/utils/format.js`, etc.

**How to wire up:**
- Import DB and utils in services/controllers as needed.
- Remove original DB/helper code from `index.js`.

**Features covered:**
- Database abstraction (SQLite, Firebase, etc.)
- Utility functions used across backend

---


## Batch 6: App Initialization and Final Cleanup
**What to move:**
- Any remaining logic not related to app setup, route mounting, or server start
- Deprecated or duplicate code

- Also move:
  - Serverless/standalone app startup logic
  - Singleton app getter (`getApp`)
  - IS_SERVERLESS, DATA_DIR, DB_PATH, PORT, etc. config
  - Any try/catch blocks for env/config loading
  - Only keep minimal code to load config, create app, mount routers, and start server

**Where to move:**
- Remove or relocate to appropriate module

**How to wire up:**
- `index.js` should only:
  - Load config/env
  - Initialize Express app
  - Mount routers
  - Start server

**Features covered:**
- Clean, maintainable app entrypoint

---


---

**After each batch:**
- Run `npm run lint` and all tests.
- Manually test key endpoints (CRUD, auth, admin, PDF, email, SharePoint, etc.).
- Only proceed if everything works.

---

**General mapping tips:**
- Always move one domain/feature at a time.
- Keep route/controller/service file names and import paths consistent.
- Test after every move.
- Update this plan if you discover new domains or helpers.

---

**Full Coverage Checklist (index.js):**
- [x] Core CRUD API routes (batches, documents, recipients, acks, progress, businesses, user-business, business uploads)
- [x] Admin APIs (tenants, modules, licenses, themes, settings, RBAC, diagnostics, health, flags, customization, notifications)
- [x] Auth, RBAC, and all middleware (logging, validation, error handling, tenant resolver, rate limiting, CORS, helmet, compression, JSON parsing, Ajv, SuperAdmin guard, audit)
- [x] Services (PDF, email, SharePoint, external users, file uploads, library, audit logs, reminders, legal consent, customization)
- [x] Database layer and utilities (adapters, schema, helpers, logger, ID, parsing, mapping, merging)
- [x] App initialization, config, serverless/standalone startup, singleton app getter

Every major feature and code section in `index.js` is mapped to a batch above. If you find a route, helper, or service not listed, add it to the appropriate batch before moving.

This approach ensures a safe, incremental migration to a modular, maintainable backend.
