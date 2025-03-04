# User Authentication System (Backend Focused)

## Overview
This is a **JWT-based authentication system** built with **Node.js, Express, MongoDB**, and **bcrypt.js** for secure password hashing. It supports user authentication, role-based access control, and password reset functionality.

## Features
- User Signup & Login with JWT Authentication
- Role-based Access Control (Admin/User)
- Protected Routes for Authenticated Users
- Forgot Password Functionality

---

## Tech Stack
- **Backend:** Node.js, Express.js
- **Database:** MongoDB (Mongoose)
- **Authentication:** JWT (JSON Web Token), bcrypt.js
- **Email Service:** Nodemailer (for password reset)

---

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/grasyPatel/Auth_System.git
   cd Auth_System
   ```
2. Install dependencies:
   ```sh
   npm install
   ```
3. Create a `.env` file in the root directory and add:
   ```env
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret_key
   EMAIL=your_email
   EMAIL_PASS=your_email_password
   ```
4. Start the server:
   ```sh
   npm start
   ```

---

## API Endpoints

### 1. User Signup
**Endpoint:** `POST /api/auth/signup`

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123",
  "role": "admin" (optional, default is "user")
}
```

**Response:**
```json
{
  "msg": "User registered successfully",
  "token": "jwt_token_here"
}
```

---

### 2. User Login
**Endpoint:** `POST /api/auth/login`

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "msg": "Login successful",
  "token": "jwt_token_here",
  "role": "user"
}
```

---

### 3. Forgot Password
**Endpoint:** `POST /api/auth/forgot-password`

**Request Body:**
```json
{
  "email": "john@example.com"
}
```

**Response:**
```json
{
  "msg": "Password reset email sent"
}
```

---

### 4. Protected Route (Authenticated Users Only)
**Endpoint:** `GET /api/auth/protected`

**Headers:**
```json
{
  "Authorization": "Bearer your_jwt_token"
}
```

**Response:**
```json
{
  "msg": "This is a protected route",
  "user": {
    "id": "user_id",
    "role": "user"
  }
}
```

---

### 5. Admin-Only Route
**Endpoint:** `GET /api/auth/admin`

**Headers:**
```json
{
  "Authorization": "Bearer your_jwt_token"
}
```

**Response:**
```json
{
  "msg": "Admin access granted"
}
```

---

### 6. Dashboard (User & Admin Access)
**Endpoint:** `GET /api/auth/dashboard`

**Headers:**
```json
{
  "Authorization": "Bearer your_jwt_token"
}
```

**Response:**
```json
{
  "msg": "Welcome, user"
}
```

---

## Testing the API
You can test the API using:
- **Postman**: Set up requests and include the JWT token in the `Authorization` header.
- **cURL**:
  ```sh
  curl -X GET http://localhost:3000/api/auth/protected -H "Authorization: Bearer your_jwt_token"
  ```
---

## Author
**Grace Patel**  
[GitHub](https://github.com/grasyPatel)  

---


