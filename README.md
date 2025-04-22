# Backend H3

A Rust-based backend API using Actix-web and SQLx with SQLite database.

## Prerequisites

- Rust (latest stable version)
- SQLite
- SQLx CLI

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd backend-h3
```

2. Create a `.env` file in the root directory:
```bash
DATABASE_URL=sqlite:data.db
JWT_SECRET=your_secret_key_here
```

3. Install SQLx CLI:
```bash
cargo install sqlx-cli --no-default-features --features sqlite
```

4. Set up the database:
```bash
sqlx database create
sqlx migrate run
```

## Development

To run the server in development mode:
```bash
cargo run
```

To run tests:
```bash
cargo test
```

## Database Migrations

To create a new migration:
```bash
sqlx migrate add <migration_name>
```

To run pending migrations:
```bash
sqlx migrate run
```

## API Documentation

The API provides the following endpoints:

- User Management:
  - `POST /api/auth/register` - Register a new user
  - `POST /api/auth/login` - Login user
  - `GET /api/users/me` - Get current user info
  - `PUT /api/users/me` - Update current user info

- GDPR Compliance:
  - `GET /api/gdpr/export` - Export user data (right of access)
  - `POST /api/gdpr/consent` - Record user consent
  - `DELETE /api/gdpr/delete` - Delete user data (right to be forgotten)

- Security:
  - `POST /api/security/scan` - Run breach detection scan (admin only)

## GDPR Features

The application implements the following GDPR-compliant features:

1. **Data Minimization**: Only essential personal data is collected
2. **Transparency**: Comprehensive privacy policy available
3. **User Rights**:
   - Right of access (data export)
   - Right to rectification (update profile)
   - Right to erasure (account deletion)
   - Consent management

4. **Privacy by Design**:
   - Encryption of sensitive data
   - Secure authentication and authorization
   - Access controls and audit logging

5. **Breach Detection & Notification**:
   - Automated breach detection system
   - Incident logging and tracking
   - CNIL notification templates
   - User impact assessment

## Data Breach Detection

The application includes a data breach detection system that:

1. Monitors for suspicious activity patterns:
   - Multiple failed login attempts
   - Unusual data export activity
   - Suspicious admin actions

2. Generates incident reports with severity assessment

3. Prepares notification templates for authorities and affected users

4. Can be scheduled to run automatically via cron job:
```bash
# Run breach detection daily at 2 AM
0 2 * * * /path/to/backend-h3/scripts/breach_scan.sh
```

## Project Structure

```
.
├── src/
│   ├── main.rs          # Application entry point
│   ├── auth.rs          # Authentication service
│   ├── gdpr.rs          # GDPR compliance features
│   ├── breach_detection.rs # Data breach detection system
│   ├── models.rs        # Data models
│   └── routes/          # Route handlers
├── migrations/          # Database migrations
├── scripts/             # Utility scripts
└── rest/                # REST API examples
```

## Technologies Used

- [Actix-web](https://actix.rs/) - Web framework
- [SQLx](https://github.com/launchbadge/sqlx) - Async SQL toolkit
- [SQLite](https://www.sqlite.org/) - Database
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken) - JWT authentication 