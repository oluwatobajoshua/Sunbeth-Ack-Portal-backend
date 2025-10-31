// Firebase Realtime Database adapter implementing the same run/query interface.
// Keeps logic simple by reading a table's data and filtering/sorting client-side for common cases.

const admin = require('firebase-admin');
const { initializeFirebase } = require('./firebase');

class FirebaseRtdbAdapter {
  constructor() {
    // Ensure app is initialized (with databaseURL)
    initializeFirebase();
    this.db = admin.database();
    this.driver = 'rtdb';
    this.lastInsertId = null;
  }

  async run(sql, params = []) {
    const op = this._parse(sql, params);
    switch (op.type) {
      case 'NOOP':
      case 'TRANSACTION':
      case 'DDL':
        return true;
      case 'INSERT':
        return await this._insert(op);
      case 'UPDATE':
        return await this._update(op);
      case 'DELETE':
        return await this._delete(op);
      default:
        throw new Error(`Unsupported RTDB write: ${op.type}`);
    }
  }

  async query(sql, params = []) {
    const sqlTrim = String(sql || '').trim();
    let m;
    m = sqlTrim.match(/^SELECT\s+1\s+AS\s+(\w+)\s*;?$/i);
    if (m) return [{ [m[1]]: 1 }];
    m = sqlTrim.match(/^SELECT\s+LAST_INSERT_ROWID\(\)\s+AS\s+(\w+)\s*;?$/i);
    if (m) return [{ [m[1]]: this.lastInsertId }];

    const op = this._parse(sql, params);
    if (op.type !== 'SELECT') {
      if (op.type === 'NOOP' || op.type === 'DDL' || op.type === 'TRANSACTION') return [];
      throw new Error(`RTDB query only supports SELECT; got ${op.type}`);
    }
    return await this._select(op);
  }

  persist() {}

  // --- Internals ---
  _parse(sql, params) {
    const upper = sql.trim().toUpperCase();
    if (/^BEGIN\b/.test(upper)) return { type: 'TRANSACTION' };
    if (/^COMMIT\b/.test(upper)) return { type: 'TRANSACTION' };
    if (/^ROLLBACK\b/.test(upper)) return { type: 'TRANSACTION' };
    if (/^PRAGMA\b/.test(upper)) return { type: 'NOOP' };
    if (/^(CREATE|ALTER|DROP|VACUUM)\b/.test(upper)) return { type: 'DDL' };

    if (upper.startsWith('SELECT')) return this._parseSelect(sql, params);
    if (upper.startsWith('INSERT')) return this._parseInsert(sql, params);
    if (upper.startsWith('UPDATE')) return this._parseUpdate(sql, params);
    if (upper.startsWith('DELETE')) return this._parseDelete(sql, params);
    throw new Error(`Unsupported SQL for RTDB: ${sql.substring(0, 40)}...`);
  }

  _parseSelect(sql, params) {
    const fromMatch = sql.match(/FROM\s+(\w+)/i);
    const table = fromMatch ? fromMatch[1] : null;
    if (!table) throw new Error('SELECT missing table');
    const whereMatch = sql.match(/WHERE\s+(.+?)(?:\s+ORDER\s+BY|\s+GROUP\s+BY|\s+LIMIT|$)/i);
    const orderMatch = sql.match(/ORDER\s+BY\s+(.+?)(?:\s+LIMIT|$)/i);
    const limitMatch = sql.match(/LIMIT\s+(\d+)/i);
    return {
      type: 'SELECT',
      table,
      conditions: this._parseWhere(whereMatch ? whereMatch[1] : '', params),
      orderBy: orderMatch ? orderMatch[1].trim() : null,
      limit: limitMatch ? parseInt(limitMatch[1], 10) : null
    };
  }

  _parseInsert(sql, params) {
    const tableMatch = sql.match(/INSERT\s+(?:OR\s+IGNORE\s+)?INTO\s+(\w+)/i);
    if (!tableMatch) throw new Error('INSERT missing table');
    const colsMatch = sql.match(/\(([^)]+)\)\s+VALUES/i);
    const cols = colsMatch ? colsMatch[1].split(',').map(s => s.trim()) : [];
    const data = {};
    // Only include values that are actually provided as params.
    // Literal INSERTs like "INSERT INTO t (a,b) VALUES ('x','y')" are not parsed here;
    // routes in this app use parameterized INSERTs. When params are missing, avoid
    // setting keys to undefined, which RTDB rejects.
    cols.forEach((c, i) => {
      if (i < params.length) data[c] = params[i];
    });
    return { type: 'INSERT', table: tableMatch[1], data };
  }

  _parseUpdate(sql, params) {
    const tableMatch = sql.match(/UPDATE\s+(\w+)/i);
    if (!tableMatch) throw new Error('UPDATE missing table');
    const setMatch = sql.match(/SET\s+(.+?)\s+WHERE/i);
    const assigns = (setMatch ? setMatch[1] : '').split(',').map(s => s.trim());
    const data = {};
    assigns.forEach((a, i) => {
      const [col] = a.split('=');
      if (i < params.length - 1) data[col.trim()] = params[i];
    });
    const whereRaw = sql.match(/WHERE\s+(.+)$/i);
    const conditions = this._parseWhere(whereRaw ? whereRaw[1] : '', params.slice(-1));
    return { type: 'UPDATE', table: tableMatch[1], data, conditions };
  }

  _parseDelete(sql, params) {
    const tableMatch = sql.match(/DELETE\s+FROM\s+(\w+)/i);
    if (!tableMatch) throw new Error('DELETE missing table');
    const whereRaw = sql.match(/WHERE\s+(.+)$/i);
    return { type: 'DELETE', table: tableMatch[1], conditions: this._parseWhere(whereRaw ? whereRaw[1] : '', params) };
  }

  _parseWhere(where, params) {
    if (!where) return null;
    // Very simple parser: capture column comparisons to a single placeholder
    const conds = [];
    // Support patterns like: LOWER(col) = LOWER(?) or LOWER(col) = ? or col = LOWER(?) or col = ?
    const re = /(LOWER\()?([\w]+)(\))?\s*(=|LIKE|>=|<=|>|<)\s*(LOWER\(\?\)|\?)/gi;
    let m; let idx = 0;
    while ((m = re.exec(where)) !== null) {
      const lower = !!m[1] || (m[5] && String(m[5]).toUpperCase().startsWith('LOWER'));
      const col = m[2];
      const op = m[4];
      let val = params[idx++];
      if (op === 'LIKE') {
        const clean = String(val).replace(/%/g, '');
        conds.push({ col, op: 'LIKE', val: clean, lower });
      } else {
        conds.push({ col, op, val, lower });
      }
    }
    return conds.length ? conds : null;
  }

  async _tableAll(table) {
    const snap = await this.db.ref('tables').child(table).get();
    const val = snap.val() || {};
    const rows = Object.keys(val).map(k => ({ id: k, ...(val[k] || {}) }));
    return rows;
  }

  _applyWhere(rows, conditions) {
    if (!conditions || !conditions.length) return rows;
    return rows.filter(r => {
      return conditions.every(c => {
        const lhs = c.lower ? String(r[c.col] ?? '').toLowerCase() : r[c.col];
        const cmpVal = c.lower ? String(c.val ?? '').toLowerCase() : c.val;
        switch (c.op) {
          case '=': return String(lhs) === String(cmpVal);
          case 'LIKE': {
            const s = String(lhs || '');
            return s.startsWith(String(cmpVal));
          }
          case '>': return lhs > cmpVal;
          case '<': return lhs < cmpVal;
          case '>=': return lhs >= cmpVal;
          case '<=': return lhs <= cmpVal;
          default: return false;
        }
      });
    });
  }

  async _select(op) {
    let rows = await this._tableAll(op.table);
    rows = this._applyWhere(rows, op.conditions);
    if (op.orderBy) {
      const [fieldRaw, dirRaw = 'asc'] = op.orderBy.split(/\s+/);
      const field = String(fieldRaw || '').trim();
      const dir = String(dirRaw || 'asc').toLowerCase();
      rows.sort((a, b) => {
        const aa = a[field]; const bb = b[field];
        if (aa === bb) return 0;
        const cmp = (aa < bb) ? -1 : 1;
        return dir === 'desc' ? -cmp : cmp;
      });
    }
    if (op.limit != null) rows = rows.slice(0, op.limit);
    return rows;
  }

  async _insert(op) {
    const ref = this.db.ref('tables').child(op.table).push();
    const id = ref.key;
    const now = new Date().toISOString();
    const data = { id, ...op.data, createdAt: now, updatedAt: now };
    await ref.set(data);
    this.lastInsertId = id;
    return id;
  }

  async _update(op) {
    const rows = await this._select({ ...op, type: 'SELECT' });
    const updates = {};
    const now = new Date().toISOString();
    for (const r of rows) {
      updates[`tables/${op.table}/${r.id}`] = { ...r, ...op.data, updatedAt: now };
    }
    if (Object.keys(updates).length) await this.db.ref().update(updates);
    return rows.length;
  }

  async _delete(op) {
    const rows = await this._select({ ...op, type: 'SELECT' });
    const updates = {};
    for (const r of rows) updates[`tables/${op.table}/${r.id}`] = null;
    if (Object.keys(updates).length) await this.db.ref().update(updates);
    return rows.length;
  }
}

module.exports = { FirebaseRtdbAdapter };
