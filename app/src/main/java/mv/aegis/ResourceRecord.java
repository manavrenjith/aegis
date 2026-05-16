package mv.aegis;

public class ResourceRecord {
    public String QName;
    public String AName;
    public String Resource;
    public int TTL;
    public long Time;
    public int uid;

    @Override
    public String toString() {
        return QName + "/" + AName + "=" + Resource;
    }
}

