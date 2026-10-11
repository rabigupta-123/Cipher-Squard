import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class CampaignEngine {
    private static final Map<String, String> iocToCampaignId = new ConcurrentHashMap<>();
    private static final Map<String, Campaign> campaigns = new ConcurrentHashMap<>();

    public static final class Campaign {
        public final String id;
        public final Set<String> iocs = Collections.synchronizedSet(new HashSet<>());
        public final List<String> emails = Collections.synchronizedList(new ArrayList<>());
        public final long startTime;

        Campaign(String id) {
            this.id = id;
            this.startTime = System.currentTimeMillis();
        }
    }

    public static synchronized String correlate(String sendingIp, String fromDomain, String subject) {
        String campaignId = null;

        // 1. Check for existing campaign via IOCs
        if (sendingIp != null && iocToCampaignId.containsKey(sendingIp)) {
            campaignId = iocToCampaignId.get(sendingIp);
        } else if (fromDomain != null && iocToCampaignId.containsKey(fromDomain)) {
            campaignId = iocToCampaignId.get(fromDomain);
        }

        // 2. Create new campaign if none found
        if (campaignId == null) {
            campaignId = "CMP-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
            Campaign c = new Campaign(campaignId);
            campaigns.put(campaignId, c);
        }

        // 3. Update Campaign and IOC mapping
        Campaign c = campaigns.get(campaignId);
        if (sendingIp != null) {
            c.iocs.add(sendingIp);
            iocToCampaignId.put(sendingIp, campaignId);
        }
        if (fromDomain != null) {
            c.iocs.add(fromDomain);
            iocToCampaignId.put(fromDomain, campaignId);
        }

        return campaignId;
    }

    public static synchronized int getCampaignSize(String campaignId) {
        Campaign c = campaigns.get(campaignId);
        return c == null ? 0 : c.emails.size();
    }

    public static synchronized void registerEmail(String campaignId, String emailId) {
        Campaign c = campaigns.get(campaignId);
        if (c != null) {
            c.emails.add(emailId);
        }
    }
}
