# Full-Stack Application Setup Script

This Bash script automates the creation of a full-stack web application with:
- C# ASP.NET Core Web API backend
- React frontend
- PostgreSQL database

## Features

- Creates a complete project structure for both backend and frontend
- Sets up authentication with ASP.NET Core Identity
- Configures Entity Framework Core for database access
- Creates React components with React Router and Bootstrap styling
- Establishes proper API connectivity between frontend and backend

## Prerequisites

- .NET SDK 8.0 or higher
- Node.js and npm
- PostgreSQL database server 
- Bash shell environment

## Usage

1. Save this script as `setup.sh`
2. Make it executable: `chmod +x setup.sh`
3. Run the script: `./setup.sh`
4. Follow the on-screen prompts to:
   - Provide a project name
   - Enter your PostgreSQL password

## Post-Setup Steps

After running the script, follow the displayed instructions to:
1. Restore NuGet packages
2. Create and apply database migrations
3. Start the backend and frontend applications

## Project Structure

The script creates a complete project structure with:
- ASP.NET Core Web API
- Entity Framework Core setup
- Authentication controllers
- React frontend with routing
- User login/registration components

## Note About PostgreSQL

Ensure PostgreSQL server is installed and running before starting the application. The script will configure the connection string based on your input.

## Default Admin Credentials

- Email: admina@strator.comx
- Password: Admin8*