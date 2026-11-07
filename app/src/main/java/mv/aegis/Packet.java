package mv.aegis;

public class Packet {
    public static final int STATUS_BLOCKED = 0;
    public static final int STATUS_ALLOWED = 1;
    public static final int STATUS_OVERFLOW = 2;

    public long time;
    public int version;
    public int protocol;
    public String flags;
    public String saddr;
    public int sport;
    public String daddr;
    public int dport;
    public String data;
    public int uid;
    public boolean allowed;
    public int status = -1;
    public boolean hasCustomStatus = false;

    public Packet() {
    }

    public void setStatus(int status) {
        this.status = status;
        this.hasCustomStatus = true;
    }

    @Override
    public String toString() {
        return "uid=" + uid + " v" + version + " p" + protocol + " " + daddr + "/" + dport;
    }
}

