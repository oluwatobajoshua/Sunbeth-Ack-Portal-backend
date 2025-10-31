// Firebase Firestore adapter for the database abstraction layer
// Implements the same interface as SQLite adapter: run(), query(), persist()

const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

/**
 * Initialize Firebase Admin SDK
 * @param {Object} config - Firebase configuration
 * @returns {admin.firestore.Firestore} Firestore instance
 */
function initializeFirebase(config = {}) {
  if (admin.apps.length > 0) {
    return admin.firestore();
  }

  const {
    FIREBASE_SERVICE_ACCOUNT_PATH,
    FIREBASE_SERVICE_ACCOUNT_JSON,
    GOOGLE_APPLICATION_CREDENTIALS,
    FIREBASE_PROJECT_ID,
    FIREBASE_DATABASE_URL,
  } = process.env;

  // Resolve service account from JSON env, file path, or ADC
  let serviceAccount = null;

  // 1) JSON provided directly (raw JSON or base64-encoded)
  if (!serviceAccount && FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      let jsonStr = FIREBASE_SERVICE_ACCOUNT_JSON.trim();
      // Attempt base64 decode first; if that fails, treat as raw JSON
      try {
        const decoded = Buffer.from(jsonStr, 'base64').toString('utf8');
        if (decoded && decoded.trim().startsWith('{')) {
          jsonStr = decoded;
        }
      } catch (_) {
        // Not base64, proceed with raw string
      }
      serviceAccount = JSON.parse(jsonStr);
    } catch (e) {
      console.warn('[firebase] Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON. Falling back to other methods. Error:', e.message);
    }
  }

  // 2) JSON file path (explicit)
  const tryLoadFile = (maybePath) => {
    try {
      if (!maybePath) return null;
      const resolved = path.isAbsolute(maybePath)
        ? maybePath
        : path.resolve(process.cwd(), maybePath);
      if (fs.existsSync(resolved)) {
        const raw = fs.readFileSync(resolved, 'utf8');
        return JSON.parse(raw);
      }
      return null;
    } catch (e) {
      console.warn(`[firebase] Failed to load service account from ${maybePath}:`, e.message);
      return null;
    }
  };

  if (!serviceAccount && FIREBASE_SERVICE_ACCOUNT_PATH) {
    serviceAccount = tryLoadFile(FIREBASE_SERVICE_ACCOUNT_PATH);
    if (!serviceAccount) {
      console.warn(`[firebase] Service account file not found at ${FIREBASE_SERVICE_ACCOUNT_PATH}.`);
    }
  }

  // 3) GOOGLE_APPLICATION_CREDENTIALS path
  if (!serviceAccount && GOOGLE_APPLICATION_CREDENTIALS) {
    serviceAccount = tryLoadFile(GOOGLE_APPLICATION_CREDENTIALS);
  }

  // Build credential
  let credential;
  if (serviceAccount) {
    credential = admin.credential.cert(serviceAccount);
  } else {
    // Use default credentials (works on Google Cloud, or if ADC is configured locally)
    console.warn('[firebase] No service account provided. Using application default credentials.');
    credential = admin.credential.applicationDefault();
  }

  const options = { credential };
  if (FIREBASE_PROJECT_ID) options.projectId = FIREBASE_PROJECT_ID;
  if (FIREBASE_DATABASE_URL) options.databaseURL = FIREBASE_DATABASE_URL;

  admin.initializeApp(options);
  return admin.firestore();
}

/**
 * Convert SQLite-style SQL to Firestore operations
 * This is a simplified mapper for common operations used in the app
 */
class FirebaseAdapter {
  constructor() {
    this.db = initializeFirebase();
    this.driver = 'firebase';
    // Track last inserted document id to emulate last_insert_rowid()
    this.lastInsertId = null;
  }

  /**
   * Execute a write operation (INSERT, UPDATE, DELETE)
   * @param {string} sql - SQL statement
   * @param {Array} params - Parameters
   */
  async run(sql, params = []) {
    const operation = this.parseSqlOperation(sql, params);

    switch (operation.type) {
      case 'NOOP':
      case 'TRANSACTION':
      case 'DDL':
        // Ignore BEGIN/COMMIT/ROLLBACK/PRAGMA/DDL in Firestore
        return true;
      case 'INSERT':
        return await this.handleInsert(operation);
      case 'UPDATE':
        return await this.handleUpdate(operation);
      case 'DELETE':
        return await this.handleDelete(operation);
      default:
        throw new Error(`Unsupported operation: ${operation.type}`);
    }
  }

  /**
   * Execute a read operation (SELECT)
   * @param {string} sql - SQL statement
   * @param {Array} params - Parameters
   * @returns {Array} Query results
   */
  async query(sql, params = []) {
    const sqlTrim = String(sql || '').trim();
    const upper = sqlTrim.toUpperCase();

    // Handle SELECT 1 as ok (canary) without FROM
    let m;
    m = sqlTrim.match(/^SELECT\s+1\s+AS\s+(\w+)\s*;?$/i);
    if (m) {
      const key = m[1];
      return [{ [key]: 1 }];
    }

    // Handle SQLite idiom: SELECT last_insert_rowid() as id
    m = sqlTrim.match(/^SELECT\s+LAST_INSERT_ROWID\(\)\s+AS\s+(\w+)\s*;?$/i);
    if (m) {
      const key = m[1];
      return [{ [key]: this.lastInsertId }];
    }

    const operation = this.parseSqlOperation(sql, params);
    if (operation.type !== 'SELECT') {
      // For DDL/NOOP/etc, return empty
      if (operation.type === 'NOOP' || operation.type === 'DDL' || operation.type === 'TRANSACTION') return [];
      throw new Error(`Query method only supports SELECT operations, got: ${operation.type}`);
    }

    return await this.handleSelect(operation);
  }

  /**
   * Persist changes (no-op for Firestore as it's already persistent)
   */
  persist() {
    // No-op for Firestore - changes are automatically persisted
  }

  /**
   * Parse SQL statement into operation object
   * This is a simplified parser for the most common patterns used in the app
   */
  parseSqlOperation(sql, params) {
    const normalizedSql = sql.trim().toUpperCase();
    // Transaction control and pragmas -> no-ops in Firestore
    if (/^BEGIN\b/.test(normalizedSql)) return { type: 'TRANSACTION', action: 'BEGIN' };
    if (/^COMMIT\b/.test(normalizedSql)) return { type: 'TRANSACTION', action: 'COMMIT' };
    if (/^ROLLBACK\b/.test(normalizedSql)) return { type: 'TRANSACTION', action: 'ROLLBACK' };
    if (/^PRAGMA\b/.test(normalizedSql)) return { type: 'NOOP' };
    // DDL statements - ignore in Firestore
    if (/^(CREATE|ALTER|DROP|VACUUM)\b/.test(normalizedSql)) return { type: 'DDL' };

    if (normalizedSql.startsWith('SELECT')) {
      return this.parseSelect(sql, params);
    } else if (normalizedSql.startsWith('INSERT')) {
      return this.parseInsert(sql, params);
    } else if (normalizedSql.startsWith('UPDATE')) {
      return this.parseUpdate(sql, params);
    } else if (normalizedSql.startsWith('DELETE')) {
      return this.parseDelete(sql, params);
    }
    
    throw new Error(`Unsupported SQL operation: ${sql.substring(0, 20)}...`);
  }

  /**
   * Parse SELECT statement
   */
  parseSelect(sql, params) {
    // Extract table name - look for FROM clause
    const fromMatch = sql.match(/FROM\s+(\w+)/i);
    if (!fromMatch) {
      throw new Error(`Could not parse table name from: ${sql}`);
    }
    
    const table = fromMatch[1];
    
    // Extract WHERE conditions
    const whereMatch = sql.match(/WHERE\s+(.+?)(?:\s+ORDER\s+BY|\s+GROUP\s+BY|\s+LIMIT|$)/i);
    const conditions = whereMatch ? this.parseWhereClause(whereMatch[1], params) : null;
    
    // Extract ORDER BY
    const orderMatch = sql.match(/ORDER\s+BY\s+(.+?)(?:\s+LIMIT|$)/i);
    const orderBy = orderMatch ? orderMatch[1].trim() : null;
    
    // Extract LIMIT
    const limitMatch = sql.match(/LIMIT\s+(\d+)/i);
    const limit = limitMatch ? parseInt(limitMatch[1]) : null;
    
    return {
      type: 'SELECT',
      table,
      conditions,
      orderBy,
      limit
    };
  }

  /**
   * Parse INSERT statement
   */
  parseInsert(sql, params) {
    // Extract table name
    const tableMatch = sql.match(/INSERT\s+(?:OR\s+IGNORE\s+)?INTO\s+(\w+)/i);
    if (!tableMatch) {
      throw new Error(`Could not parse table name from INSERT: ${sql}`);
    }
    
    const table = tableMatch[1];
    
    // Extract columns and values
    const columnsMatch = sql.match(/\(([^)]+)\)\s+VALUES/i);
    if (!columnsMatch) {
      throw new Error(`Could not parse columns from INSERT: ${sql}`);
    }
    
    const columns = columnsMatch[1].split(',').map(col => col.trim());
    
    // Create data object
    const data = {};
    columns.forEach((col, index) => {
      if (index < params.length) {
        data[col] = params[index];
      }
    });
    
    return {
      type: 'INSERT',
      table,
      data
    };
  }

  /**
   * Parse UPDATE statement
   */
  parseUpdate(sql, params) {
    // Extract table name
    const tableMatch = sql.match(/UPDATE\s+(\w+)/i);
    if (!tableMatch) {
      throw new Error(`Could not parse table name from UPDATE: ${sql}`);
    }
    
    const table = tableMatch[1];
    
    // Extract SET clause
    const setMatch = sql.match(/SET\s+(.+?)\s+WHERE/i);
    if (!setMatch) {
      throw new Error(`Could not parse SET clause from UPDATE: ${sql}`);
    }
    
    // Parse WHERE clause
    const whereMatch = sql.match(/WHERE\s+(.+)$/i);
    const conditions = whereMatch ? this.parseWhereClause(whereMatch[1], params.slice(-1)) : null;
    
    // Parse SET assignments (simplified - assumes SET col1=?, col2=?, ...)
    const setClause = setMatch[1];
    const assignments = setClause.split(',').map(assignment => assignment.trim());
    const data = {};
    
    assignments.forEach((assignment, index) => {
      const [column] = assignment.split('=');
      if (index < params.length - 1) { // -1 because last param is usually for WHERE
        data[column.trim()] = params[index];
      }
    });
    
    return {
      type: 'UPDATE',
      table,
      data,
      conditions
    };
  }

  /**
   * Parse DELETE statement
   */
  parseDelete(sql, params) {
    // Extract table name
    const tableMatch = sql.match(/DELETE\s+FROM\s+(\w+)/i);
    if (!tableMatch) {
      throw new Error(`Could not parse table name from DELETE: ${sql}`);
    }
    
    const table = tableMatch[1];
    
    // Extract WHERE conditions
    const whereMatch = sql.match(/WHERE\s+(.+)$/i);
    const conditions = whereMatch ? this.parseWhereClause(whereMatch[1], params) : null;
    
    return {
      type: 'DELETE',
      table,
      conditions
    };
  }

  /**
   * Parse WHERE clause into Firestore query conditions
   */
  parseWhereClause(whereClause, params) {
    // Simplified WHERE parser - handles basic equality and LIKE operations
    // For production, you'd want a more robust SQL parser
    
    const conditions = [];
    let paramIndex = 0;
    
    // Handle simple conditions like "column = ?" or "LOWER(column) = ?"
    const simpleConditionRegex = /(?:LOWER\()?(\w+)(?:\))?\s*(=|LIKE|>|<|>=|<=)\s*\?/gi;
    let match;
    
    while ((match = simpleConditionRegex.exec(whereClause)) !== null) {
      const [, column, operator] = match;
      const value = params[paramIndex++];
      
      if (operator === '=') {
        conditions.push({ field: column, operator: '==', value });
      } else if (operator === 'LIKE') {
        // Firestore doesn't support LIKE, so we'll do a simple prefix match
        // Remove % wildcards and use array-contains for simple cases
        const cleanValue = String(value).replace(/%/g, '');
        conditions.push({ field: column, operator: '>=', value: cleanValue });
        conditions.push({ field: column, operator: '<', value: cleanValue + '\uf8ff' });
      } else {
        conditions.push({ field: column, operator, value });
      }
    }
    
    return conditions.length > 0 ? conditions : null;
  }

  /**
   * Handle SELECT operations
   */
  async handleSelect(operation) {
    let query = this.db.collection(operation.table);

    // Apply WHERE conditions
    if (operation.conditions) {
      for (const condition of operation.conditions) {
        query = query.where(condition.field, condition.operator, condition.value);
      }
    }

    // Determine if we should sort client-side by document ID
    let clientSortById = false;
    let clientSortDir = 'asc';
    if (operation.orderBy) {
      const [fieldRaw, dirRaw = 'asc'] = operation.orderBy.split(/\s+/);
      const field = String(fieldRaw || '').trim();
      const direction = String(dirRaw || 'asc').toLowerCase();
      if (/^id$/i.test(field)) {
        // Firestore cannot order by documentId using a normal field string.
        // We'll fetch and sort client-side by the doc.id instead.
        clientSortById = true;
        clientSortDir = (direction === 'desc') ? 'desc' : 'asc';
      } else {
        query = query.orderBy(field, direction);
      }
    }

    // Apply LIMIT only when not client-sorting; if client-sorting, apply after sorting
    if (operation.limit && !clientSortById) {
      query = query.limit(operation.limit);
    }

    const snapshot = await query.get();
    let rows = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    if (clientSortById) {
      rows.sort((a, b) => {
        const aa = String(a.id || '');
        const bb = String(b.id || '');
        if (aa === bb) return 0;
        const cmp = aa < bb ? -1 : 1;
        return clientSortDir === 'desc' ? -cmp : cmp;
      });
      if (operation.limit) rows = rows.slice(0, operation.limit);
    }

    return rows;
  }

  /**
   * Handle INSERT operations
   */
  async handleInsert(operation) {
    const docRef = this.db.collection(operation.table).doc();
    await docRef.set({
      ...operation.data,
      id: docRef.id,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    this.lastInsertId = docRef.id;
    return docRef.id;
  }

  /**
   * Handle UPDATE operations
   */
  async handleUpdate(operation) {
    let query = this.db.collection(operation.table);
    
    // Apply WHERE conditions to find documents to update
    if (operation.conditions) {
      for (const condition of operation.conditions) {
        query = query.where(condition.field, condition.operator, condition.value);
      }
    }
    
    const snapshot = await query.get();
    const batch = this.db.batch();
    
    snapshot.docs.forEach(doc => {
      batch.update(doc.ref, {
        ...operation.data,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });
    
    await batch.commit();
    return snapshot.size;
  }

  /**
   * Handle DELETE operations
   */
  async handleDelete(operation) {
    let query = this.db.collection(operation.table);
    
    // Apply WHERE conditions to find documents to delete
    if (operation.conditions) {
      for (const condition of operation.conditions) {
        query = query.where(condition.field, condition.operator, condition.value);
      }
    }
    
    const snapshot = await query.get();
    const batch = this.db.batch();
    
    snapshot.docs.forEach(doc => {
      batch.delete(doc.ref);
    });
    
    await batch.commit();
    return snapshot.size;
  }
}

module.exports = { FirebaseAdapter, initializeFirebase };