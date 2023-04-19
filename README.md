# Rust and Axum Framework: JWT Access and Refresh Tokens

In this article, you'll learn how to build a secure and efficient backend API in Rust with JWT access and refresh tokens functionality. We'll leverage the high-performance Axum framework and SQLX to store data in a PostgreSQL database.

![Rust and Axum Framework: JWT Access and Refresh Tokens](https://codevoweb.com/wp-content/uploads/2023/04/Rust-and-Axum-Framework-JWT-Access-and-Refresh-Tokens.webp)

## Topics Covered

- Set up and Run the Axum API on your Machine
- Run the Axum API with a Frontend App
- Set up the Rust Project with Cargo
- Launch PostgreSQL, Redis and pgAdmin Servers
- Perform Database Migration with SQLx-CLI
- Load the Environment Variables into the App
- Connect the Axum Server to the Redis and Postgres Servers
- Define the SQLX Database Model
- Define the API Response Structs
- Generate the RS256 Private and Public Keys
- Create Helper Functions to Sign and Verify the JWTs
    - Function to Sign the JWT using the Private Key
    - Function to Verify the JWT using the Public Key
- Create an Axum JWT Middleware Guard
- Implement the JWT Authentication Route Handlers
    - Create Utility Functions
    - Route Handler to Register Users
    - Route Handler to Sign In Users
    - Route Handler to Refresh the JWTs
    - Route Handler to Logout Users
    - Route Handler to Fetch the Authenticated User
    - The Complete Code of the Route Handlers
- Create Axum Routes for the Handler Functions
- Register the Axum Router and Set up CORS
- Conclusion


Read the entire article here: [https://codevoweb.com/rust-and-axum-jwt-access-and-refresh-tokens/](https://codevoweb.com/rust-and-axum-jwt-access-and-refresh-tokens/)

