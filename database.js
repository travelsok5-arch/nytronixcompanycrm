const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const fs = require('fs');

const dbPath = path.join(__dirname, 'cybernytronix.db');
const backupsDir = path.join(__dirname, 'backups');

// Ensure backups directory exists
if (!fs.existsSync(backupsDir)) {
    fs.mkdirSync(backupsDir, { recursive: true });
}

let db = null;

// Function to initialize database connection
const initializeDatabaseConnection = () => {
    return new Promise((resolve, reject) => {
        // Close existing connection if any
        if (db) {
            db.close((err) => {
                if (err) {
                    console.error('❌ Error closing existing database:', err);
                }
                // Continue with new connection
                createNewConnection(resolve, reject);
            });
        } else {
            createNewConnection(resolve, reject);
        }
    });
};

const createNewConnection = (resolve, reject) => {
    db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
            console.error('❌ Error opening database:', err);
            reject(err);
        } else {
            console.log('✅ Connected to SQLite database');
            db.run('PRAGMA foreign_keys = ON');
            db.run('PRAGMA journal_mode = WAL'); // Better performance
            initializeDatabase()
                .then(() => resolve(db))
                .catch(reject);
        }
    });
};

// Initialize database tables
const initializeDatabase = () => {
    return new Promise((resolve, reject) => {
        console.log('🔄 Starting database initialization...');

        // Create tables in correct order to handle foreign keys
        const tables = [
            // Users table first (no dependencies)
            `CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                department TEXT,
                position TEXT,
                status TEXT DEFAULT 'active',
                phone TEXT,
                profile_pic TEXT,
                last_login DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,

            // Clients table (depends on users)
            `CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                company TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                address TEXT,
                website TEXT,
                services TEXT,
                industry TEXT,
                status TEXT DEFAULT 'active',
                contract_value DECIMAL(10,2) DEFAULT 0,
                contract_start DATE,
                contract_end DATE,
                assigned_to INTEGER,
                created_by INTEGER,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,

            // Leads table (depends on users)
            `CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                company TEXT,
                email TEXT NOT NULL,
                phone TEXT,
                source TEXT,
                status TEXT DEFAULT 'new',
                priority TEXT DEFAULT 'medium',
                value DECIMAL(10,2) DEFAULT 0,
                notes TEXT,
                assigned_to INTEGER,
                created_by INTEGER,
                next_followup DATE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,

            // Projects table (depends on clients and users)
            `CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                client_id INTEGER,
                status TEXT DEFAULT 'planning',
                priority TEXT DEFAULT 'medium',
                start_date DATE,
                end_date DATE,
                budget DECIMAL(10,2) DEFAULT 0,
                progress INTEGER DEFAULT 0,
                assigned_to INTEGER,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients (id),
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,

            // Tasks table (depends on projects and users)
            `CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                project_id INTEGER,
                assigned_to INTEGER,
                status TEXT DEFAULT 'pending',
                priority TEXT DEFAULT 'medium',
                due_date DATE,
                time_spent INTEGER DEFAULT 0,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects (id),
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,

            // Tickets table (depends on clients and users)
            `CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                client_id INTEGER,
                type TEXT DEFAULT 'technical_support',
                priority TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                assigned_to INTEGER,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients (id),
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,

            // Vulnerabilities table (depends on projects and users)
            `CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                project_id INTEGER,
                assigned_to INTEGER,
                cvss_score DECIMAL(3,1),
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects (id),
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,

            // Incidents table (depends on clients and users)
            `CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                client_id INTEGER,
                assigned_to INTEGER,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients (id),
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,

            // Security alerts table
            `CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                client_id INTEGER,
                assigned_to INTEGER,
                source TEXT,
                alert_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients (id),
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`,

            // Chat messages table (depends on users)
            `CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                message TEXT NOT NULL,
                room TEXT DEFAULT 'general',
                edited BOOLEAN DEFAULT 0,
                deleted BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )`,

            // System logs table (depends on users)
            `CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                description TEXT,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )`,

            // Backup logs table (depends on users)
            `CREATE TABLE IF NOT EXISTS backup_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                size_bytes INTEGER,
                backup_type TEXT DEFAULT 'full',
                status TEXT DEFAULT 'success',
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )`
        ];

        let tableIndex = 0;
        const createNextTable = () => {
            if (tableIndex >= tables.length) {
                console.log('✅ All tables created successfully');
                createAdminUser()
                    .then(() => resolve())
                    .catch(reject);
                return;
            }
            
            db.run(tables[tableIndex], (err) => {
                if (err) {
                    console.error(`❌ Error creating table ${tableIndex + 1}:`, err);
                } else {
                    console.log(`✅ Table ${tableIndex + 1} created/verified`);
                }
                tableIndex++;
                createNextTable();
            });
        };

        createNextTable();
    });
};

// Create only admin user
const createAdminUser = () => {
    return new Promise((resolve, reject) => {
        console.log('👤 Creating admin user...');
        
        const adminPassword = bcrypt.hashSync('admin@12345', 10);
        db.run(`INSERT OR IGNORE INTO users (name, email, password, role, department, position, phone, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, 
            ['System Administrator', 'admin@cybernytronix.com', adminPassword, 'admin', 'IT', 'System Administrator', '+1-555-0001', 'active'],
            function(err) {
                if (err) {
                    console.error('❌ Error creating admin user:', err);
                    reject(err);
                } else {
                    console.log('✅ Admin user created/verified');
                    console.log('🔑 Default login: admin@cybernytronix.com / admin@12345');
                    console.log('🎉 Database initialization completed successfully!');
                    resolve();
                }
            });
    });
};

// Backup database function
const backupDatabase = () => {
    return new Promise((resolve, reject) => {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = path.join(__dirname, 'backups', `cybernytronix_backup_${timestamp}.db`);
        
        // Ensure backups directory exists
        const backupsDir = path.join(__dirname, 'backups');
        if (!fs.existsSync(backupsDir)) {
            fs.mkdirSync(backupsDir, { recursive: true });
        }

        // Create backup by copying the database file
        fs.copyFile(dbPath, backupFile, (err) => {
            if (err) {
                console.error('❌ Backup failed:', err);
                reject(err);
            } else {
                console.log('✅ Backup completed successfully:', backupFile);
                
                // Log backup in database
                const stats = fs.statSync(backupFile);
                db.run(
                    'INSERT INTO backup_logs (filename, size_bytes, backup_type, status, created_by) VALUES (?, ?, ?, ?, ?)',
                    [path.basename(backupFile), stats.size, 'full', 'success', 1],
                    function(err) {
                        if (err) {
                            console.error('❌ Error logging backup:', err);
                        }
                        resolve(backupFile);
                    }
                );
            }
        });
    });
};

// Function to restore database
const restoreDatabase = (backupFilePath) => {
    return new Promise((resolve, reject) => {
        console.log('🔄 Starting database restore...');
        
        // Close current database connection
        db.close((err) => {
            if (err) {
                console.error('❌ Error closing database:', err);
                reject(err);
                return;
            }
            
            console.log('✅ Database connection closed');
            
            try {
                // Copy backup file to current database
                fs.copyFileSync(backupFilePath, dbPath);
                console.log('✅ Database file restored');
                
                // Reinitialize database connection
                initializeDatabaseConnection()
                    .then(() => {
                        console.log('✅ Database reconnected successfully after restore');
                        resolve();
                    })
                    .catch(reject);
            } catch (copyError) {
                console.error('❌ Error restoring database:', copyError);
                reject(copyError);
            }
        });
    });
};

// Handle database errors
if (db) {
    db.on('error', (err) => {
        console.error('❌ Database error:', err);
    });
}

// Initialize database connection on startup
initializeDatabaseConnection().catch(err => {
    console.error('❌ Failed to initialize database:', err);
});

module.exports = {
    getDb: () => db,
    backupDatabase,
    restoreDatabase,
    initializeDatabaseConnection
};