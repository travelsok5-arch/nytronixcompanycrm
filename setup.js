const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

console.log('🚀 Setting up Cyber Nytronix CRM...');

// Create backups directory if it doesn't exist
const backupsDir = path.join(__dirname, 'backups');
if (!fs.existsSync(backupsDir)) {
    fs.mkdirSync(backupsDir, { recursive: true });
    console.log('✅ Created backups directory');
}

// Check if node_modules exists
if (!fs.existsSync(path.join(__dirname, 'node_modules'))) {
    console.log('📦 Installing dependencies...');
    exec('npm install', (error, stdout, stderr) => {
        if (error) {
            console.error('Error installing dependencies:', error);
            return;
        }
        console.log('✅ Dependencies installed successfully');
        startApplication();
    });
} else {
    startApplication();
}

function startApplication() {
    console.log('🎉 Setup completed! Starting application...');
    console.log('💡 Run "npm start" to start the server');
}