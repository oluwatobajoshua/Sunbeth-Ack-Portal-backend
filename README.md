# Sunbeth Document Acknowledgment Backend

A Node.js/Express backend API for the Sunbeth Document Acknowledgment Portal, providing SQLite-based data management and business process automation.

## 🚀 Features

- **RESTful API** with Express.js
- **SQLite Database** using sql.js (WASM-based, no native dependencies)
- **RBAC System** with comprehensive permission management
- **Document Management** API endpoints
- **Batch Processing** for acknowledgment workflows
- **Business Entity** CRUD operations
- **User Authentication** support
- **Comprehensive Logging** system
- **Excel/CSV Import** capabilities

## 📋 Prerequisites

- Node.js (v16 or higher)
- npm or yarn

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd sunbeth_doc_backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the server**
   ```bash
   npm start
   ```
   
   The API will be available at `http://localhost:4000`

## 📁 Project Structure

```
sunbeth_doc_backend/
├── index.js              # Main server file with all routes and logic
├── package.json          # Dependencies and scripts
├── data/                 # SQLite database files
│   ├── sunbeth.db        # Main database
│   ├── sunbeth-backup.db # Backup database
│   └── sunbeth - Copy.db # Copy of database
└── src/                  # Additional source files (if any)
```

## 🔧 Available Scripts

- `npm start` - Start the production server
- `npm run dev` - Start the development server

## 🔗 API Endpoints

### Authentication & Users
- `POST /api/users` - Create new user
- `GET /api/users` - Get all users
- `GET /api/users/:id` - Get user by ID
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user

### Businesses
- `GET /api/businesses` - Get all businesses
- `POST /api/businesses` - Create new business
- `PUT /api/businesses/:id` - Update business
- `DELETE /api/businesses/:id` - Delete business

### Batches
- `GET /api/batches` - Get all batches
- `POST /api/batches` - Create new batch
- `GET /api/batches/:id` - Get batch by ID
- `PUT /api/batches/:id` - Update batch
- `DELETE /api/batches/:id` - Delete batch

### Documents
- `GET /api/documents` - Get all documents
- `POST /api/documents` - Create new document
- `GET /api/documents/:id` - Get document by ID
- `PUT /api/documents/:id` - Update document
- `DELETE /api/documents/:id` - Delete document

### Recipients & Progress
- `GET /api/recipients` - Get all recipients
- `POST /api/recipients` - Create new recipient
- `GET /api/progress/:batchId` - Get batch progress
- `POST /api/progress` - Update progress

### Analytics
- `GET /api/analytics` - Get system analytics
- `GET /api/health` - Health check endpoint

### SharePoint Integration (Completion PDF Upload)
- Settings
   - `GET /api/settings/sharepoint` → `{ siteName, libraryName }` (public read)
   - `PUT /api/admin/settings` with `{ sharepoint_site_name, sharepoint_library_name }` (admin-only)
- Upload endpoint
   - `POST /api/sharepoint/upload-completion-pdf`
   - Body: `{ userEmail, businessName, departmentName, fileName, contentBytes, emailFieldName? }`
   - Description: Resolves Site → Library → Drive, navigates `BusinessName/DepartmentName`, locates the user folder by matching a list item email field (supports `Employee Email`, `Employee_x0020_Email`, `EmployeeEmail`, or override via `emailFieldName`), then uploads the PDF.
   - Response: `{ ok: true, item: { id, name, webUrl } }` on success; error with message on misconfiguration or auth failure.
- Environment (app token): `MS_TENANT_ID`, `MS_CLIENT_ID`, `MS_CLIENT_SECRET`.

### Email Mirror PDFs
- `POST /api/emails/user-completion-pdf` → returns base64 PDF of the user completion email.
- `POST /api/emails/admin-completion-pdf` → returns base64 PDF of the admin completion email.

## 🗄️ Database Schema

The SQLite database includes the following main tables:

- **Users** - User authentication and profiles
- **Businesses** - Organization/department entities  
- **Batches** - Document acknowledgment batches
- **Documents** - Document metadata and references
- **Recipients** - Batch recipients and assignments
- **Progress** - Acknowledgment tracking
- **Audit Logs** - System activity logging

## 🔒 RBAC Permissions

The system includes 15 permission categories:

- **General**: Admin access, settings management, debug logs
- **Analytics**: View and export analytics
- **Batches**: Create, edit, delete batches and manage recipients/documents
- **Communications**: Send notifications
- **Content**: Upload documents
- **Data**: Manage businesses
- **Security**: Manage roles and permissions

## 🔧 Configuration

The server can be configured through environment variables or by modifying the configuration in `index.js`:

- **Port**: Default 4000 (configurable via `PORT` env var)
- **Database Driver**: Select with `DB_DRIVER` (default `sqlite`)
   - `sqlite` uses sql.js + file at `./data/sunbeth.db`
   - `firebase` for Firestore and `rtdb` for Firebase Realtime Database (see Production notes below)
   - Placeholders exist for `postgres`, `mysql`, `mssql` (add adapters in `src/db/adapter.js`)
- **CORS**: Enabled for frontend integration

## 📊 Logging

The server includes comprehensive logging for:
- API requests and responses
- Database operations
- Error handling
- Batch processing operations
- Authentication events

## 🚀 Deployment

### Local Development
```bash
npm start
```

### Production Deployment
We deploy this backend to Vercel’s serverless platform.

### Environment Variables
- `PORT` - Server port (default: 4000)
- `NODE_ENV` - Environment (development/production)
- `DB_DRIVER` - Database driver (`sqlite`, `firebase`, `rtdb`, `libsql`, `turso`)

### Using Firebase RTDB on Vercel (Production)
When running with `DB_DRIVER=rtdb`, the backend uses the Firebase Admin SDK against your Realtime Database. Configure these environment variables in your Vercel Project (Settings → Environment Variables):

- `DB_DRIVER` = `rtdb`
- `FIREBASE_PROJECT_ID` = your Firebase project id (e.g. `sunbeth-ack-portal`)
- `FIREBASE_DATABASE_URL` = your RTDB URL (e.g. `https://<project-id>-default-rtdb.firebaseio.com/`)
- One of the following for credentials:
   - `FIREBASE_SERVICE_ACCOUNT_JSON` = the service account JSON, either pasted directly as raw JSON or base64-encoded
   - OR `FIREBASE_SERVICE_ACCOUNT_PATH` = path to a JSON file in the deployed filesystem (not recommended on Vercel)

Notes:
- The code automatically detects base64 vs raw JSON in `FIREBASE_SERVICE_ACCOUNT_JSON`.
- Don’t commit service account keys to the repo. A sample is provided at `data/serviceAccount.example.json`. The actual `data/serviceAccount.json` is git-ignored.
- Firestore support is also available with `DB_DRIVER=firebase` using the same credentials variables.

Verify after deploy:
- Call `GET /api/health` → should return `{ ok: true }`.
- Call `GET /api/diag/db` → should return `{ driver: "rtdb", canary: { ok: 1 } }`.
- Library and proxy endpoints should continue to function unchanged (`/api/library/list`, `/api/proxy`).

## 🔄 Database Management

The SQLite database is file-based and included in the `data/` directory. For local dev:

For production on Vercel, prefer a cloud database (e.g., Firebase RTDB with `DB_DRIVER=rtdb`) instead of SQLite, since serverless filesystems are ephemeral. If you do use SQLite, bundle `sql-wasm.wasm` as configured in `vercel.json`.

1. Backup Strategy: If using SQLite locally, take regular backups of `data/`.
2. Migration: Database schema changes should be handled carefully.
3. Performance: Consider indexing or switching to a managed database for larger datasets.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is private and proprietary. All rights reserved.

## 🐛 Troubleshooting

### Common Issues

**Port Already in Use**
```bash
# Find and kill process using port 4000
netstat -ano | findstr :4000
taskkill /PID <process-id> /F
```

**Database Issues**
- Ensure `data/` directory exists
- Check file permissions
- Verify SQLite file is not corrupted

**CORS Issues**
- Verify frontend URL is allowed in CORS configuration
- Check that API endpoints are correctly proxied

## 📞 Support

For issues and questions:
- Check the API logs for error details
- Verify database connectivity
- Ensure all dependencies are installed correctly

---

**Built with ❤️ for the Sunbeth Document Acknowledgment System**
