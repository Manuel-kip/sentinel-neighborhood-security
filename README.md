# Sentinel Neighborhood — deployment state

This repository is separate from the original neighborhood security system.

## Components
- Railway service: `sentinel-web` (PHP/Apache)
- Railway service: `MySQL` (MySQL 8 with persistent volume)
- `database/schema.sql`: application database tables (not yet imported)
- `public/index.php`: **deployment verification page only**, not the complete university application.

## Before accepting the project
1. Publish the full PHP application source and assets.
2. Import the database schema into the independent Railway MySQL database.
3. Create demo accounts securely, with passwords stored outside GitHub.
4. Test administrator, officer, and resident permissions; check-in/out; incidents; announcements; CSV reports.
5. Test backup and restore in an independent database.
6. Verify HTTPS cookies, authorization, CSRF, and error handling.

Never use real residents' personal data in a public demo.
