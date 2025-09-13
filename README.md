# Secure AI Rules Directory

A comprehensive collection of security guidelines for building safe, reliable, and compliant AI systems in 2025.

## Overview

This application provides a searchable directory of security rules and best practices for AI development, covering various programming languages and frameworks commonly used in AI applications.

## Features

- **Searchable Directory**: Find security rules by keyword or tag
- **Framework-Specific Guidelines**: Dedicated security rules for different tech stacks
- **Copy-to-Clipboard**: Easy copying of rules for documentation or implementation
- **Responsive Design**: Works on desktop and mobile devices
- **Real-time Search**: Instant filtering as you type

## Available Rule Sets

The directory currently includes security guidelines for:

- **Angular Security** - Security best practices for Angular applications
- **Ruby Security** - Comprehensive security guidelines for Ruby and Ruby on Rails
- **Python Security** - Security practices for Python applications and AI/ML frameworks
- **Node.js Security** - Security guidelines for Node.js and JavaScript applications
- **Java Security** - Security best practices for Java applications
- **.NET Security** - Security guidelines for .NET applications

## Getting Started

### Prerequisites

- Node.js 18 or higher
- npm or yarn

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/fcerullo-cycubix/secure-ai-rules.git
   cd secure-ai-rules
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run the development server:
   ```bash
   npm run dev
   ```

4. Open [http://localhost:3000](http://localhost:3000) in your browser

### Building for Production

```bash
npm run build
npm start
```

## Project Structure

```
src/
├── app/                    # Next.js app directory
│   ├── layout.tsx         # Root layout
│   ├── page.tsx           # Home page
│   └── secure-ai-rules/   # Rules directory page
├── components/            # React components
│   └── SecureAIDirectory.tsx
└── rules/                 # Security rule definitions
    ├── index.ts           # Rules export
    ├── angular-security.ts
    ├── ruby-security.ts
    ├── python-security.ts
    ├── nodejs-security.ts
    ├── java-security.ts
    └── dotnet-security.ts
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Technology Stack

- **Framework**: Next.js 15
- **UI**: React with Tailwind CSS
- **Icons**: Lucide React
- **TypeScript**: For type safety
- **Deployment**: GitHub Pages compatible

## License

This project is open source and available under the [MIT License](LICENSE).

## Updates

This directory is regularly updated to reflect the latest AI security challenges and industry developments. Last updated: 2025.