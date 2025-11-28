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

let db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Error opening database:', err);
    } else {
        console.log('✅ Connected to SQLite database');
        db.run('PRAGMA foreign_keys = ON');
        initializeDatabase();
    }
});

// Initialize database tables
const initializeDatabase = () => {
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
            insertSampleData();
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
};

// Insert sample data function
const insertSampleData = () => {
    console.log('📊 Inserting sample data...');
    
    // Create admin user
    const adminPassword = bcrypt.hashSync('admin@12345', 10);
    db.run(`INSERT OR IGNORE INTO users (name, email, password, role, department, position, phone, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, 
        ['System Administrator', 'admin@cybernytronix.com', adminPassword, 'admin', 'IT', 'System Administrator', '+1-555-0001', 'active'],
        function(err) {
            if (err) {
                console.error('❌ Error creating admin user:', err);
            } else {
                console.log('✅ Admin user created/verified');
            }
        });

    // Create sample users
    const userPassword = bcrypt.hashSync('user@123', 10);
    const sampleUsers = [
        ['John Smith', 'john.smith@cybernytronix.com', userPassword, 'user', 'Sales', 'Sales Executive', '+1-555-0002', 'active'],
        ['Sarah Johnson', 'sarah.johnson@cybernytronix.com', userPassword, 'user', 'Cyber Security', 'Security Analyst', '+1-555-0003', 'active'],
        ['Mike Wilson', 'mike.wilson@cybernytronix.com', userPassword, 'user', 'IT', 'IT Specialist', '+1-555-0004', 'active'],
        ['Emily Davis', 'emily.davis@cybernytronix.com', userPassword, 'user', 'SOC', 'SOC Analyst', '+1-555-0005', 'active'],
        ['David Brown', 'david.brown@cybernytronix.com', userPassword, 'admin', 'Management', 'Project Manager', '+1-555-0006', 'active']
    ];

    let userCount = 0;
    sampleUsers.forEach((user) => {
        db.run(`INSERT OR IGNORE INTO users (name, email, password, role, department, position, phone, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, user, (err) => {
            if (err && !err.message.includes('UNIQUE constraint failed')) {
                console.error('❌ Error creating sample user:', err);
            }
            userCount++;
            if (userCount === sampleUsers.length) {
                console.log('✅ Sample users created/verified');
                createSampleClients();
            }
        });
    });
};

const createSampleClients = () => {
    const sampleClients = [
        ['Robert Wilson', 'ABC Corp', 'robert@abccorp.com', '+1-555-2001', '123 Business Ave, New York', 'www.abccorp.com', 'Cybersecurity, Network Monitoring, SOC', 'Technology', 'active', 25000.00, '2024-01-01', '2024-12-31', 2, 1, 'Regular client with ongoing projects'],
        ['Jennifer Lee', 'XYZ Ltd', 'jennifer@xyzltd.com', '+1-555-2002', '456 Corporate Blvd, Chicago', 'www.xyzltd.com', 'IT Consulting, Cloud Services, Penetration Testing', 'Finance', 'active', 18000.00, '2024-02-01', '2024-11-30', 3, 1, 'New client signed last month'],
        ['Michael Brown', 'Global Systems', 'michael@globalsystems.com', '+1-555-2003', '789 Enterprise St, Boston', 'www.globalsystems.com', 'Security Audit, Compliance, Incident Response', 'Healthcare', 'active', 32000.00, '2024-01-15', '2024-12-15', 4, 1, 'Enterprise client with multiple locations']
    ];

    let clientCount = 0;
    sampleClients.forEach((client) => {
        db.run(`INSERT OR IGNORE INTO clients (name, company, email, phone, address, website, services, industry, status, contract_value, contract_start, contract_end, assigned_to, created_by, notes) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, client, (err) => {
            if (err) {
                console.error('❌ Error creating sample client:', err);
            }
            clientCount++;
            if (clientCount === sampleClients.length) {
                console.log('✅ Sample clients created');
                createSampleLeads();
            }
        });
    });
};

const createSampleLeads = () => {
    const sampleLeads = [
        ['Michael Brown', 'Tech Solutions Inc', 'michael@techsolutions.com', '+1-555-3001', 'website', 'new', 'high', 15000.00, 2, 1, '2024-03-15', 'Interested in cybersecurity services'],
        ['Emily Davis', 'Global Enterprises', 'emily@globalent.com', '+1-555-3002', 'referral', 'contacted', 'medium', 22000.00, 3, 1, '2024-03-20', 'Referred by existing client'],
        ['Chris Johnson', 'StartUp Tech', 'chris@startuptech.com', '+1-555-3003', 'social', 'qualified', 'high', 18000.00, 4, 1, '2024-03-25', 'Fast-growing startup needs security solutions']
    ];

    let leadCount = 0;
    sampleLeads.forEach((lead) => {
        db.run(`INSERT OR IGNORE INTO leads (name, company, email, phone, source, status, priority, value, assigned_to, created_by, next_followup, notes) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, lead, (err) => {
            if (err) {
                console.error('❌ Error creating sample lead:', err);
            }
            leadCount++;
            if (leadCount === sampleLeads.length) {
                console.log('✅ Sample leads created');
                createSampleProjects();
            }
        });
    });
};

const createSampleProjects = () => {
    const sampleProjects = [
        ['Network Security Implementation', 'Implement comprehensive network security solutions for ABC Corp', 1, 'in_progress', 'high', '2024-01-01', '2024-06-30', 50000.00, 65, 3, 1],
        ['Cloud Migration Project', 'Migrate XYZ Ltd infrastructure to cloud with enhanced security', 2, 'planning', 'medium', '2024-02-15', '2024-08-15', 75000.00, 20, 4, 1],
        ['Security Audit & Compliance', 'Complete security audit and compliance assessment for Global Systems', 3, 'completed', 'high', '2024-01-10', '2024-03-20', 30000.00, 100, 2, 1]
    ];

    let projectCount = 0;
    sampleProjects.forEach((project) => {
        db.run(`INSERT OR IGNORE INTO projects (name, description, client_id, status, priority, start_date, end_date, budget, progress, assigned_to, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, project, (err) => {
            if (err) {
                console.error('❌ Error creating sample project:', err);
            }
            projectCount++;
            if (projectCount === sampleProjects.length) {
                console.log('✅ Sample projects created');
                createSampleTasks();
            }
        });
    });
};

const createSampleTasks = () => {
    const sampleTasks = [
        ['Configure Firewall', 'Set up and configure enterprise firewall rules', 1, 3, 'completed', 'high', '2024-01-15', 8, 1],
        ['Security Assessment', 'Perform initial security assessment and vulnerability scan', 1, 4, 'in_progress', 'high', '2024-02-28', 16, 1],
        ['Cloud Setup', 'Configure cloud infrastructure and security groups', 2, 3, 'pending', 'medium', '2024-03-10', 0, 1]
    ];

    let taskCount = 0;
    sampleTasks.forEach((task) => {
        db.run(`INSERT OR IGNORE INTO tasks (title, description, project_id, assigned_to, status, priority, due_date, time_spent, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, task, (err) => {
            if (err) {
                console.error('❌ Error creating sample task:', err);
            }
            taskCount++;
            if (taskCount === sampleTasks.length) {
                console.log('✅ Sample tasks created');
                createSampleTickets();
            }
        });
    });
};

const createSampleTickets = () => {
    const sampleTickets = [
        ['Login Issues', 'Users unable to login to the portal', 1, 'technical_support', 'high', 'open', 3, 1],
        ['Slow Performance', 'Application running very slow during peak hours', 2, 'performance', 'medium', 'in_progress', 4, 1],
        ['Feature Request', 'Add two-factor authentication to user accounts', 1, 'feature', 'low', 'open', 2, 1]
    ];

    let ticketCount = 0;
    sampleTickets.forEach((ticket) => {
        db.run(`INSERT OR IGNORE INTO tickets (title, description, client_id, type, priority, status, assigned_to, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ticket, (err) => {
            if (err) {
                console.error('❌ Error creating sample ticket:', err);
            }
            ticketCount++;
            if (ticketCount === sampleTickets.length) {
                console.log('✅ Sample tickets created');
                createSampleVulnerabilities();
            }
        });
    });
};

const createSampleVulnerabilities = () => {
    const sampleVulnerabilities = [
        ['SQL Injection Vulnerability', 'Found SQL injection in login form', 'high', 'open', 1, 4, 8.5, 1],
        ['XSS in Contact Form', 'Cross-site scripting vulnerability in contact form', 'medium', 'open', 2, 3, 6.2, 1],
        ['Weak Password Policy', 'No strong password enforcement', 'low', 'fixed', 1, 2, 4.1, 1]
    ];

    let vulnCount = 0;
    sampleVulnerabilities.forEach((vuln) => {
        db.run(`INSERT OR IGNORE INTO vulnerabilities (title, description, severity, status, project_id, assigned_to, cvss_score, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, vuln, (err) => {
            if (err) {
                console.error('❌ Error creating sample vulnerability:', err);
            }
            vulnCount++;
            if (vulnCount === sampleVulnerabilities.length) {
                console.log('✅ Sample vulnerabilities created');
                createSampleIncidents();
            }
        });
    });
};

const createSampleIncidents = () => {
    const sampleIncidents = [
        ['Unauthorized Access Attempt', 'Multiple failed login attempts from unknown IP', 'high', 'open', 1, 4, 1],
        ['Malware Detection', 'Antivirus detected malware on employee workstation', 'medium', 'in_progress', 2, 3, 1],
        ['Data Breach Alert', 'Potential data breach detected by security system', 'critical', 'open', 1, 2, 1]
    ];

    let incidentCount = 0;
    sampleIncidents.forEach((incident) => {
        db.run(`INSERT OR IGNORE INTO incidents (title, description, severity, status, client_id, assigned_to, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?)`, incident, (err) => {
            if (err) {
                console.error('❌ Error creating sample incident:', err);
            }
            incidentCount++;
            if (incidentCount === sampleIncidents.length) {
                console.log('✅ Sample incidents created');
                createSampleSecurityAlerts();
            }
        });
    });
};

const createSampleSecurityAlerts = () => {
    const sampleAlerts = [
        ['Suspicious Network Activity', 'Unusual network traffic patterns detected', 'medium', 'open', 1, 3, 'IDS', 1],
        ['Failed Login Attempts', 'Multiple failed login attempts from external IP', 'high', 'investigating', 2, 4, 'Firewall', 1],
        ['Malware Signature Detected', 'Known malware signature detected in email attachment', 'critical', 'open', 1, 2, 'Antivirus', 1]
    ];

    let alertCount = 0;
    sampleAlerts.forEach((alert) => {
        db.run(`INSERT OR IGNORE INTO security_alerts (title, description, severity, status, client_id, assigned_to, source, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, alert, (err) => {
            if (err) {
                console.error('❌ Error creating sample security alert:', err);
            }
            alertCount++;
            if (alertCount === sampleAlerts.length) {
                console.log('✅ Sample security alerts created');
                createSampleChatMessages();
            }
        });
    });
};

const createSampleChatMessages = () => {
    const sampleMessages = [
        [1, 'Hello team! Welcome to Cyber Nytronix CRM.', 'general'],
        [2, 'Hi everyone! Looking forward to working with you all.', 'general'],
        [3, 'Good morning! Any updates on the network security project?', 'general'],
        [4, 'The firewall configuration is complete. Moving to testing phase.', 'general']
    ];

    let messageCount = 0;
    sampleMessages.forEach((message) => {
        db.run(`INSERT OR IGNORE INTO chat_messages (user_id, message, room) 
                VALUES (?, ?, ?)`, message, (err) => {
            if (err) {
                console.error('❌ Error creating sample chat message:', err);
            }
            messageCount++;
            if (messageCount === sampleMessages.length) {
                console.log('✅ Sample chat messages created');
                console.log('🎉 Database initialization completed successfully!');
                console.log('🔑 Default login: admin@cybernytronix.com / admin@12345');
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

// Function to reinitialize database after restore
const reinitializeDatabase = () => {
    console.log('🔄 Reinitializing database connection...');
    db.close((err) => {
        if (err) {
            console.error('❌ Error closing database:', err);
            return;
        }
        
        // Reopen database connection
        db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                console.error('❌ Error reopening database:', err);
            } else {
                console.log('✅ Database reconnected successfully');
                db.run('PRAGMA foreign_keys = ON');
            }
        });
    });
};

// Handle database errors
db.on('error', (err) => {
    console.error('❌ Database error:', err);
});

module.exports = {
    db,
    backupDatabase,
    initializeDatabase,
    reinitializeDatabase
};