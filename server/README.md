# Express Server with TypeScript

This project is a simple Express server built using TypeScript. It serves as a template for creating scalable and maintainable web applications.

## Project Structure

```
express-server
├── src
│   ├── app.ts                # Entry point of the application
│   ├── controllers           # Contains controllers for handling requests
│   │   └── index.ts          # Index controller
│   ├── routes                # Contains route definitions
│   │   └── index.ts          # Route setup
│   └── types                 # Custom types and interfaces
│       └── index.ts          # Type definitions
├── package.json              # NPM package configuration
├── tsconfig.json             # TypeScript configuration
└── README.md                 # Project documentation
```

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd express-server
   ```

2. **Install dependencies:**
   ```
   npm install
   ```

3. **Compile TypeScript:**
   ```
   npm run build
   ```

4. **Run the server:**
   ```
   npm start
   ```

## Usage

- The server listens on a specified port (default is 3000).
- You can access the root route at `http://localhost:3000/`.

## Contributing

Feel free to submit issues or pull requests for improvements or bug fixes.