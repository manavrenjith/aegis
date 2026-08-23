package mv.aegis;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDoneException;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteStatement;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.util.Log;

import androidx.preference.PreferenceManager;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class AegisDatabase extends SQLiteOpenHelper {
    private static final String TAG = "Aegis.Database";
    private static final String DB_NAME = "Aegis";
    private static final int DB_VERSION = 23;
    private static final int MSG_LOG = 1;
    private static final int MSG_ACCESS = 2;
    private static final long SYN_SNI_DELAY = 5000L;

    private static AegisDatabase dh = null;
    private static final List<LogChangedListener> logChangedListeners = new ArrayList<>();
    private static final List<AccessChangedListener> accessChangedListeners = new ArrayList<>();
    private static HandlerThread hthread = null;
    private static Handler handler = null;

    private SharedPreferences prefs;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    static {
        hthread = new HandlerThread("AegisDatabase");
        hthread.start();
        handler = new Handler(hthread.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                handleChangedNotification(msg);
            }
        };
    }

    public static synchronized AegisDatabase getInstance(Context context) {
        if (dh == null) {
            dh = new AegisDatabase(context.getApplicationContext());
        }
        return dh;
    }

    private AegisDatabase(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
        prefs = PreferenceManager.getDefaultSharedPreferences(context);
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        super.onConfigure(db);
        db.enableWriteAheadLogging();
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        createTableLog(db);
        createTableAccess(db);
        createTableDns(db);
        createTableApp(db);
        createTableBlocklist(db);
    }

    private void createTableLog(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE log ("
                + "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "time INTEGER NOT NULL,"
                + "version INTEGER,"
                + "protocol INTEGER,"
                + "flags TEXT,"
                + "saddr TEXT,"
                + "sport INTEGER,"
                + "daddr TEXT,"
                + "dport INTEGER,"
                + "dname TEXT,"
                + "uid INTEGER,"
                + "data TEXT,"
                + "allowed INTEGER,"
                + "connection INTEGER,"
                + "interactive INTEGER,"
                + "threat_type TEXT"
                + ")");

        db.execSQL("CREATE INDEX idx_log_time ON log(time)");
        db.execSQL("CREATE INDEX idx_log_dest ON log(daddr)");
        db.execSQL("CREATE INDEX idx_log_dname ON log(dname)");
        db.execSQL("CREATE INDEX idx_log_dport ON log(dport)");
        db.execSQL("CREATE INDEX idx_log_uid ON log(uid)");
    }

    private void createTableAccess(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE access ("
                + "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "uid INTEGER NOT NULL,"
                + "version INTEGER NOT NULL,"
                + "protocol INTEGER NOT NULL,"
                + "daddr TEXT NOT NULL,"
                + "dport INTEGER NOT NULL,"
                + "time INTEGER NOT NULL,"
                + "allowed INTEGER,"
                + "block INTEGER NOT NULL,"
                + "sent INTEGER,"
                + "received INTEGER,"
                + "connections INTEGER"
                + ")");

        db.execSQL("CREATE UNIQUE INDEX idx_access ON access(uid, version, protocol, daddr, dport)");
        db.execSQL("CREATE INDEX idx_access_daddr ON access(daddr)");
        db.execSQL("CREATE INDEX idx_access_block ON access(block)");
    }

    private void createTableDns(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE dns ("
                + "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "time INTEGER NOT NULL,"
                + "qname TEXT NOT NULL,"
                + "aname TEXT NOT NULL,"
                + "resource TEXT NOT NULL,"
                + "ttl INTEGER,"
                + "uid INTEGER"
                + ")");

        db.execSQL("CREATE UNIQUE INDEX idx_dns ON dns(qname, aname, resource)");
        db.execSQL("CREATE INDEX idx_dns_resource ON dns(resource)");
    }

    private void createTableApp(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE app ("
                + "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "package TEXT,"
                + "label TEXT,"
                + "system INTEGER NOT NULL,"
                + "internet INTEGER NOT NULL,"
                + "enabled INTEGER NOT NULL"
                + ")");

        db.execSQL("CREATE UNIQUE INDEX idx_package ON app(package)");
    }

    private void createTableBlocklist(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE blocklist ("
                + "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "domain TEXT NOT NULL,"
                + "source TEXT,"
                + "time INTEGER"
                + ")");

        db.execSQL("CREATE UNIQUE INDEX idx_blocklist_domain ON blocklist(domain)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.beginTransaction();
        try {
            if (oldVersion < 2) {
                if (!columnExists(db, "log", "version")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN version INTEGER");
                }
                if (!columnExists(db, "log", "protocol")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN protocol INTEGER");
                }
                if (!columnExists(db, "log", "uid")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN uid INTEGER");
                }
                oldVersion = 2;
            }

            if (oldVersion < 3) {
                if (!columnExists(db, "log", "port")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN port INTEGER");
                }
                if (!columnExists(db, "log", "flags")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN flags TEXT");
                }
                oldVersion = 3;
            }

            if (oldVersion < 4) {
                if (!columnExists(db, "log", "connection")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN connection INTEGER");
                }
                oldVersion = 4;
            }

            if (oldVersion < 5) {
                if (!columnExists(db, "log", "interactive")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN interactive INTEGER");
                }
                oldVersion = 5;
            }

            if (oldVersion < 6) {
                if (!columnExists(db, "log", "allowed")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN allowed INTEGER");
                }
                oldVersion = 6;
            }

            if (oldVersion < 7) {
                db.execSQL("DROP TABLE IF EXISTS log");
                createTableLog(db);
                oldVersion = 8;
            }

            if (oldVersion < 9) {
                createTableAccess(db);
                oldVersion = 9;
            }

            if (oldVersion < 10) {
                db.execSQL("DROP TABLE IF EXISTS log");
                db.execSQL("DROP TABLE IF EXISTS access");
                createTableLog(db);
                createTableAccess(db);
                oldVersion = 10;
            }

            if (oldVersion < 12) {
                db.execSQL("DROP TABLE IF EXISTS access");
                createTableAccess(db);
                oldVersion = 12;
            }

            if (oldVersion < 13) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_dport ON log(dport)");
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_dname ON log(dname)");
                oldVersion = 13;
            }

            if (oldVersion < 14) {
                createTableDns(db);
                oldVersion = 14;
            }

            if (oldVersion < 15) {
                db.execSQL("DROP TABLE IF EXISTS access");
                createTableAccess(db);
                oldVersion = 15;
            }

            if (oldVersion < 17) {
                if (!columnExists(db, "access", "sent")) {
                    db.execSQL("ALTER TABLE access ADD COLUMN sent INTEGER");
                }
                if (!columnExists(db, "access", "received")) {
                    db.execSQL("ALTER TABLE access ADD COLUMN received INTEGER");
                }
                oldVersion = 17;
            }

            if (oldVersion < 18) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_access_block ON access(block)");
                db.execSQL("DROP INDEX IF EXISTS idx_dns");
                db.execSQL("CREATE UNIQUE INDEX idx_dns ON dns(qname, aname, resource)");
                oldVersion = 18;
            }

            if (oldVersion < 19) {
                if (!columnExists(db, "access", "connections")) {
                    db.execSQL("ALTER TABLE access ADD COLUMN connections INTEGER");
                }
                oldVersion = 19;
            }

            if (oldVersion < 20) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_access_daddr ON access(daddr)");
                oldVersion = 20;
            }

            if (oldVersion < 21) {
                createTableApp(db);
                oldVersion = 21;
            }

            if (oldVersion < 22) {
                if (!columnExists(db, "dns", "uid")) {
                    db.execSQL("ALTER TABLE dns ADD COLUMN uid INTEGER");
                }
                oldVersion = 22;
            }

            if (oldVersion < 23) {
                if (!columnExists(db, "log", "threat_type")) {
                    db.execSQL("ALTER TABLE log ADD COLUMN threat_type TEXT");
                }
                db.execSQL("DROP TABLE IF EXISTS blocklist");
                createTableBlocklist(db);
                oldVersion = 23;
            }

            if (oldVersion == DB_VERSION) {
                db.setTransactionSuccessful();
            } else {
                throw new IllegalArgumentException("Upgrade failed old=" + oldVersion + " new=" + newVersion);
            }
        } finally {
            db.endTransaction();
        }
    }

    private boolean columnExists(SQLiteDatabase db, String table, String column) {
        Cursor cursor = null;
        try {
            cursor = db.rawQuery("SELECT * FROM " + table + " LIMIT 0", null);
            return cursor.getColumnIndex(column) >= 0;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    public void insertLog(Packet packet, String dname, int connection, boolean interactive) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = getWritableDatabase();

            if (packet.protocol == 6 && "sni".equals(packet.data)) {
                long from = packet.time - SYN_SNI_DELAY;
                long to = packet.time + SYN_SNI_DELAY;
                db.delete(
                        "log",
                        "protocol = 6 AND uid = ? AND version = ? AND saddr = ? AND daddr = ? AND dport = ? AND data = ? AND time BETWEEN ? AND ?",
                        new String[]{
                                String.valueOf(packet.uid),
                                String.valueOf(packet.version),
                                packet.saddr,
                                packet.daddr,
                                String.valueOf(packet.dport),
                                "syn",
                                String.valueOf(from),
                                String.valueOf(to)
                        }
                );
            }

            ContentValues cv = new ContentValues();
            cv.put("time", packet.time);
            cv.put("version", packet.version >= 0 ? packet.version : null);
            cv.put("protocol", packet.protocol >= 0 ? packet.protocol : null);
            cv.put("flags", packet.flags);
            cv.put("saddr", packet.saddr);
            cv.put("sport", packet.sport >= 0 ? packet.sport : null);
            cv.put("daddr", packet.daddr);
            cv.put("dport", packet.dport >= 0 ? packet.dport : null);
            cv.put("dname", dname);
            cv.put("data", packet.data);
            cv.put("uid", packet.uid >= 0 ? packet.uid : null);
            cv.put("allowed", packet.allowed ? 1 : 0);
            cv.put("connection", connection);
            cv.put("interactive", interactive ? 1 : 0);

            long id = db.insert("log", null, cv);
            if (id < 0) {
                Log.e(TAG, "insert log failed");
            }

            notifyLogChanged();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void insertThreatLog(Packet packet, String dname, String threatType, int connection, boolean interactive) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = getWritableDatabase();

            ContentValues cv = new ContentValues();
            cv.put("time", packet.time);
            cv.put("version", packet.version >= 0 ? packet.version : null);
            cv.put("protocol", packet.protocol >= 0 ? packet.protocol : null);
            cv.put("flags", packet.flags);
            cv.put("saddr", packet.saddr);
            cv.put("sport", packet.sport >= 0 ? packet.sport : null);
            cv.put("daddr", packet.daddr);
            cv.put("dport", packet.dport >= 0 ? packet.dport : null);
            cv.put("dname", dname);
            cv.put("data", packet.data);
            cv.put("uid", packet.uid >= 0 ? packet.uid : null);
            cv.put("allowed", packet.allowed ? 1 : 0);
            cv.put("connection", connection);
            cv.put("interactive", interactive ? 1 : 0);
            cv.put("threat_type", threatType);

            long id = db.insert("log", null, cv);
            if (id < 0) {
                Log.e(TAG, "insert threat log failed");
            }

            notifyLogChanged();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public long getBlocklistCount() {
        lock.readLock().lock();
        Cursor cursor = null;
        try {
            cursor = getReadableDatabase().rawQuery("SELECT COUNT(*) FROM blocklist", null);
            if (cursor.moveToFirst()) {
                return cursor.getLong(0);
            }
            return 0L;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            lock.readLock().unlock();
        }
    }

    public int insertBlocklistDomains(List<String> domains, String source) {
        if (domains == null || domains.isEmpty()) {
            return 0;
        }
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = getWritableDatabase();
            long now = System.currentTimeMillis();
            int inserted = 0;
            db.beginTransaction();
            try {
                for (String domain : domains) {
                    if (domain == null || domain.isEmpty()) {
                        continue;
                    }
                    ContentValues cv = new ContentValues();
                    cv.put("domain", domain);
                    cv.put("source", source);
                    cv.put("time", now);
                    long id = db.insertWithOnConflict("blocklist", null, cv, SQLiteDatabase.CONFLICT_IGNORE);
                    if (id >= 0) {
                        inserted++;
                    }
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            return inserted;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Set<String> loadBlocklistDomains() {
        lock.readLock().lock();
        Cursor cursor = null;
        try {
            Set<String> domains = new HashSet<>();
            cursor = getReadableDatabase().rawQuery("SELECT domain FROM blocklist", null);
            while (cursor.moveToNext()) {
                String domain = cursor.getString(0);
                if (domain != null && !domain.isEmpty()) {
                    domains.add(domain);
                }
            }
            return domains;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            lock.readLock().unlock();
        }
    }

    // ------------------------------------------------------------------
    // User-managed blocklist (in-app "Manage blocklist" screen)
    // ------------------------------------------------------------------

    /**
     * Adds a single domain to the blocklist. The unique index on {@code domain} makes this a
     * no-op for duplicates. Returns true only if a new row was actually inserted.
     *
     * @param source provenance tag, e.g. "user" for user-added, "bundled" for the seed list.
     */
    public boolean addBlocklistDomain(String domain, String source) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        lock.writeLock().lock();
        try {
            ContentValues cv = new ContentValues();
            cv.put("domain", domain);
            cv.put("source", source);
            cv.put("time", System.currentTimeMillis());
            long id = getWritableDatabase()
                    .insertWithOnConflict("blocklist", null, cv, SQLiteDatabase.CONFLICT_IGNORE);
            return id >= 0;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Removes a domain from the blocklist. Returns the number of rows deleted (0 or 1). */
    public int deleteBlocklistDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return 0;
        }
        lock.writeLock().lock();
        try {
            return getWritableDatabase().delete("blocklist", "domain = ?", new String[]{domain});
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * All blocklist entries for the manager UI. User-added domains are listed first, then the
     * bundled samples; both groups are alphabetical. Each entry is {domain, source} and
     * {@code source} may be null for legacy rows.
     */
    public List<String[]> listBlocklist() {
        lock.readLock().lock();
        Cursor cursor = null;
        try {
            List<String[]> out = new ArrayList<>();
            cursor = getReadableDatabase().rawQuery(
                    "SELECT domain, source FROM blocklist ORDER BY "
                            + "CASE WHEN source = 'user' THEN 0 ELSE 1 END, domain ASC", null);
            while (cursor.moveToNext()) {
                out.add(new String[]{cursor.getString(0), cursor.getString(1)});
            }
            return out;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            lock.readLock().unlock();
        }
    }

    /**
     * Number of log rows recorded as auto-blocked threats (e.g. known-phishing / blocklist
     * hits). Typosquat detections are flagged rather than blocked, so they are not counted.
     */
    public int getThreatBlockedCount() {
        lock.readLock().lock();
        Cursor cursor = null;
        try {
            cursor = getReadableDatabase().rawQuery(
                    "SELECT COUNT(*) FROM log WHERE threat_type IS NOT NULL AND allowed = 0", null);
            if (cursor.moveToFirst()) {
                return cursor.getInt(0);
            }
            return 0;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            lock.readLock().unlock();
        }
    }

    /**
     * Up to {@code limit} apps with the most threat detections (blocked or flagged), most
     * first. Each entry is {uid, count}; a uid of -1 means the detection could not be
     * attributed to an app (e.g. it was captured on the DNS response path).
     */
    public List<int[]> getTopThreatApps(int limit) {
        lock.readLock().lock();
        Cursor cursor = null;
        try {
            List<int[]> out = new ArrayList<>();
            cursor = getReadableDatabase().rawQuery(
                    "SELECT uid, COUNT(*) AS c FROM log WHERE threat_type IS NOT NULL "
                            + "GROUP BY uid ORDER BY c DESC LIMIT ?",
                    new String[]{String.valueOf(limit)});
            while (cursor.moveToNext()) {
                int uid = cursor.isNull(0) ? -1 : cursor.getInt(0);
                int count = cursor.getInt(1);
                out.add(new int[]{uid, count});
            }
            return out;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            lock.readLock().unlock();
        }
    }

    public boolean updateAccess(Packet packet, String dname, int block) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = getWritableDatabase();
            String resolvedAddress = dname == null ? packet.daddr : dname;

            ContentValues cv = new ContentValues();
            cv.put("time", packet.time);
            cv.put("allowed", packet.allowed ? 1 : 0);
            if (block >= 0) {
                cv.put("block", block);
            }

            int rows = db.update(
                    "access",
                    cv,
                    "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?",
                    new String[]{
                            String.valueOf(packet.uid),
                            String.valueOf(packet.version),
                            String.valueOf(packet.protocol),
                            resolvedAddress,
                            String.valueOf(packet.dport)
                    }
            );

            if (rows == 0) {
                cv.put("uid", packet.uid);
                cv.put("version", packet.version);
                cv.put("protocol", packet.protocol);
                cv.put("daddr", resolvedAddress);
                cv.put("dport", packet.dport);
                if (block < 0) {
                    cv.put("block", 0);
                }
                db.insert("access", null, cv);
            }

            notifyAccessChanged();
            return rows == 0;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void updateUsage(Usage usage, String dname) {
        lock.writeLock().lock();
        Cursor cursor = null;
        try {
            SQLiteDatabase db = getWritableDatabase();
            String resolvedAddress = dname == null ? usage.DAddr : dname;
            String[] selectionArgs = new String[]{
                    String.valueOf(usage.Uid),
                    String.valueOf(usage.Version),
                    String.valueOf(usage.Protocol),
                    resolvedAddress,
                    String.valueOf(usage.DPort)
            };

            long sent = usage.Sent;
            long received = usage.Received;
            long connections = 1L;

            cursor = db.query(
                    "access",
                    new String[]{"sent", "received", "connections"},
                    "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?",
                    selectionArgs,
                    null,
                    null,
                    null
            );

            if (cursor.moveToFirst()) {
                sent += cursor.isNull(0) ? 0L : cursor.getLong(0);
                received += cursor.isNull(1) ? 0L : cursor.getLong(1);
                connections += cursor.isNull(2) ? 0L : cursor.getLong(2);
            }

            ContentValues cv = new ContentValues();
            cv.put("time", usage.Time);
            cv.put("sent", sent);
            cv.put("received", received);
            cv.put("connections", connections);

            int rows = db.update(
                    "access",
                    cv,
                    "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?",
                    selectionArgs
            );

            if (rows != 1) {
                cv.put("uid", usage.Uid);
                cv.put("version", usage.Version);
                cv.put("protocol", usage.Protocol);
                cv.put("daddr", resolvedAddress);
                cv.put("dport", usage.DPort);
                cv.put("block", 0);
                db.insert("access", null, cv);
            }

            notifyAccessChanged();
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            lock.writeLock().unlock();
        }
    }

    public long[] getTodayUsage() {
        lock.readLock().lock();
        Cursor cursor = null;
        try {
            Calendar calendar = Calendar.getInstance();
            calendar.set(Calendar.HOUR_OF_DAY, 0);
            calendar.set(Calendar.MINUTE, 0);
            calendar.set(Calendar.SECOND, 0);
            calendar.set(Calendar.MILLISECOND, 0);
            long startOfDay = calendar.getTimeInMillis();

            cursor = getReadableDatabase().rawQuery(
                    "SELECT COALESCE(SUM(sent),0) AS total_sent, COALESCE(SUM(received),0) AS total_received FROM access WHERE time >= ?",
                    new String[]{String.valueOf(startOfDay)}
            );

            if (cursor.moveToFirst()) {
                return new long[]{cursor.getLong(0), cursor.getLong(1)};
            }
            return new long[]{0L, 0L};
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            lock.readLock().unlock();
        }
    }

    public Cursor getLog(boolean udp, boolean tcp, boolean other, boolean allowed, boolean blocked) {
        return getLog(udp, tcp, other, allowed, blocked, true);
    }

    public Cursor getLog(boolean udp, boolean tcp, boolean other, boolean allowed, boolean blocked, boolean unknown) {
        lock.readLock().lock();
        try {
            List<String> where = new ArrayList<>();

            List<String> protocolFilter = new ArrayList<>();
            if (udp) {
                protocolFilter.add("protocol = 17");
            }
            if (tcp) {
                protocolFilter.add("protocol = 6");
            }
            if (other) {
                protocolFilter.add("(protocol <> 6 AND protocol <> 17)");
            }
            if (protocolFilter.isEmpty()) {
                where.add("1 = 0");
            } else {
                where.add("(" + String.join(" OR ", protocolFilter) + ")");
            }

            List<String> allowedFilter = new ArrayList<>();
            if (allowed) {
                allowedFilter.add("allowed = 1");
            }
            if (blocked) {
                allowedFilter.add("allowed = 0");
            }
            if (allowedFilter.isEmpty()) {
                where.add("1 = 0");
            } else {
                where.add("(" + String.join(" OR ", allowedFilter) + ")");
            }

            if (!unknown) {
                where.add("uid >= 0");
            }

            String sql = "SELECT ID AS _id, * FROM log WHERE " + String.join(" AND ", where) + " ORDER BY time DESC";
            return getReadableDatabase().rawQuery(sql, null);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor searchLog(String find) {
        lock.readLock().lock();
        try {
            String[] args = new String[]{"%" + find + "%", "%" + find + "%", find, find};
            return getReadableDatabase().rawQuery(
                    "SELECT ID AS _id, * FROM log WHERE daddr LIKE ? OR dname LIKE ? OR dport = ? OR uid = ? ORDER BY time DESC",
                    args
            );
        } finally {
            lock.readLock().unlock();
        }
    }

    public void clearLog(int uid) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = getWritableDatabase();
            if (uid < 0) {
                db.delete("log", null, null);
            } else {
                db.delete("log", "uid = ?", new String[]{String.valueOf(uid)});
            }
            db.execSQL("VACUUM");
            notifyLogChanged();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void cleanupLog(long time) {
        lock.writeLock().lock();
        try {
            getWritableDatabase().delete("log", "time < ?", new String[]{String.valueOf(time)});
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Cursor getUsageByApp() {
        lock.readLock().lock();
        try {
            return getReadableDatabase().rawQuery(
                    "SELECT uid AS _id, uid, COALESCE(SUM(sent),0) AS total_sent, COALESCE(SUM(received),0) AS total_received, COALESCE(SUM(connections),0) AS total_connections "
                            + "FROM access WHERE sent > 0 OR received > 0 GROUP BY uid ORDER BY (total_sent + total_received) DESC",
                    null
            );
        } finally {
            lock.readLock().unlock();
        }
    }

    public String getQName(int uid, String ip) {
        lock.readLock().lock();
        SQLiteStatement statement = null;
        try {
            statement = getReadableDatabase().compileStatement(
                    "SELECT qname FROM dns WHERE resource = ? ORDER BY (uid = ?) DESC LIMIT 1"
            );
            statement.bindString(1, ip);
            statement.bindLong(2, uid);
            return statement.simpleQueryForString();
        } catch (SQLiteDoneException ignored) {
            return null;
        } finally {
            if (statement != null) {
                statement.close();
            }
            lock.readLock().unlock();
        }
    }

    public Cursor getAccess(int uid) {
        lock.readLock().lock();
        try {
            return getReadableDatabase().rawQuery(
                    "SELECT ID AS _id, * FROM access WHERE uid = ? ORDER BY time DESC LIMIT 250",
                    new String[]{String.valueOf(uid)}
            );
        } finally {
            lock.readLock().unlock();
        }
    }

    public void clearAccess(int uid, boolean keeprules) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = getWritableDatabase();
            if (keeprules) {
                db.delete("access", "uid = ? AND block < 0", new String[]{String.valueOf(uid)});
            } else {
                db.delete("access", "uid = ?", new String[]{String.valueOf(uid)});
            }
            notifyAccessChanged();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void resetUsage(int uid) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = getWritableDatabase();
            ContentValues cv = new ContentValues();
            cv.putNull("sent");
            cv.putNull("received");
            cv.putNull("connections");

            if (uid < 0) {
                db.update("access", cv, null, null);
            } else {
                db.update("access", cv, "uid = ?", new String[]{String.valueOf(uid)});
            }

            notifyAccessChanged();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Cursor getApp(String packageName) {
        lock.readLock().lock();
        try {
            return getReadableDatabase().query(
                    "app",
                    new String[]{"ID AS _id", "package", "label", "system", "internet", "enabled"},
                    "package = ?",
                    new String[]{packageName},
                    null,
                    null,
                    null,
                    "1"
            );
        } finally {
            lock.readLock().unlock();
        }
    }

    public void addApp(String packageName, String label, boolean system, boolean internet, boolean enabled) {
        lock.writeLock().lock();
        try {
            ContentValues cv = new ContentValues();
            cv.put("package", packageName);
            cv.put("label", label);
            cv.put("system", system ? 1 : 0);
            cv.put("internet", internet ? 1 : 0);
            cv.put("enabled", enabled ? 1 : 0);
            getWritableDatabase().insertWithOnConflict("app", null, cv, SQLiteDatabase.CONFLICT_REPLACE);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void clearApps() {
        lock.writeLock().lock();
        try {
            getWritableDatabase().delete("app", null, null);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public long getHostCount(int uid, boolean includeBlocked) {
        lock.readLock().lock();
        Cursor cursor = null;
        try {
            StringBuilder sql = new StringBuilder("SELECT COUNT(DISTINCT daddr) FROM access WHERE uid = ?");
            if (includeBlocked) {
                sql.append(" AND block >= 0");
            }
            cursor = getReadableDatabase().rawQuery(sql.toString(), new String[]{String.valueOf(uid)});
            if (cursor.moveToFirst()) {
                return cursor.getLong(0);
            }
            return 0L;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            lock.readLock().unlock();
        }
    }

    public interface LogChangedListener {
        void onChanged();
    }

    public interface AccessChangedListener {
        void onChanged();
    }

    public static void addLogChangedListener(LogChangedListener listener) {
        synchronized (logChangedListeners) {
            logChangedListeners.add(listener);
        }
    }

    public static void removeLogChangedListener(LogChangedListener listener) {
        synchronized (logChangedListeners) {
            logChangedListeners.remove(listener);
        }
    }

    public static void addAccessChangedListener(AccessChangedListener listener) {
        synchronized (accessChangedListeners) {
            accessChangedListeners.add(listener);
        }
    }

    public static void removeAccessChangedListener(AccessChangedListener listener) {
        synchronized (accessChangedListeners) {
            accessChangedListeners.remove(listener);
        }
    }

    private void notifyLogChanged() {
        if (handler != null) {
            handler.sendEmptyMessage(MSG_LOG);
        }
    }

    private void notifyAccessChanged() {
        if (handler != null) {
            handler.sendEmptyMessage(MSG_ACCESS);
        }
    }

    private static void handleChangedNotification(Message msg) {
        if (handler != null && handler.hasMessages(msg.what)) {
            return;
        }

        try {
            Thread.sleep(250L);
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            return;
        }

        if (handler != null && handler.hasMessages(msg.what)) {
            return;
        }

        if (msg.what == MSG_LOG) {
            List<LogChangedListener> listeners;
            synchronized (logChangedListeners) {
                listeners = new ArrayList<>(logChangedListeners);
            }
            for (LogChangedListener listener : listeners) {
                try {
                    listener.onChanged();
                } catch (Throwable throwable) {
                    Log.e(TAG, "log listener failed", throwable);
                }
            }
        } else if (msg.what == MSG_ACCESS) {
            List<AccessChangedListener> listeners;
            synchronized (accessChangedListeners) {
                listeners = new ArrayList<>(accessChangedListeners);
            }
            for (AccessChangedListener listener : listeners) {
                try {
                    listener.onChanged();
                } catch (Throwable throwable) {
                    Log.e(TAG, "access listener failed", throwable);
                }
            }
        }
    }
}

