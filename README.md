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
  - `POST /api/users/register` - Register a new user
  - `POST /api/users/login` - Login user
  - `GET /api/users/me` - Get current user info

## Project Structure

```
.
├── src/
│   ├── main.rs          # Application entry point
│   ├── api.rs           # API routes and handlers
│   ├── database.rs      # Database connection and utilities
│   ├── models/          # Data models
│   └── routes/          # Route handlers
├── migrations/          # Database migrations
└── rest/               # REST API examples
```

## Technologies Used

- [Actix-web](https://actix.rs/) - Web framework
- [SQLx](https://github.com/launchbadge/sqlx) - Async SQL toolkit
- [SQLite](https://www.sqlite.org/) - Database
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken) - JWT authentication 