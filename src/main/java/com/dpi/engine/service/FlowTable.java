package com.dpi.engine.service;

import com.dpi.engine.model.AppType;
import com.dpi.engine.model.Flow;
import com.dpi.engine.model.FiveTuple;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe flow tracking table.
 * Equivalent to the C++ unordered_map<FlowKey, FlowInfo>.
 */
@Component
public class FlowTable {

    private final ConcurrentHashMap<FiveTuple, Flow> table = new ConcurrentHashMap<>();
    private final Set<String> blockedApps = ConcurrentHashMap.newKeySet();

    /** Get or create a flow for this five-tuple */
    public Flow getOrCreate(FiveTuple tuple) {
        return table.computeIfAbsent(tuple, Flow::new);
    }

    /** Lookup an existing flow (null if not found) */
    public Flow lookup(FiveTuple tuple) {
        return table.get(tuple);
    }

    /** Register an app name to be blocked */
    public void blockApp(String appDisplayName) {
        blockedApps.add(appDisplayName.toLowerCase());
    }

    /** Unregister a blocked app */
    public void unblockApp(String appDisplayName) {
        blockedApps.remove(appDisplayName.toLowerCase());
    }

    /** Clear all blocked apps */
    public void clearBlocked() {
        blockedApps.clear();
    }

    public Set<String> getBlockedApps() {
        return Collections.unmodifiableSet(blockedApps);
    }

    public boolean isAppBlocked(AppType appType) {
        return blockedApps.contains(appType.getDisplayName().toLowerCase());
    }

    /** All flows as a snapshot list */
    public List<Flow> allFlows() {
        return new ArrayList<>(table.values());
    }

    /** Total number of tracked flows */
    public int size() { return table.size(); }

    /** Clear all flows (between PCAP analyses) */
    public void clear() { table.clear(); }

    /** Stats per application type */
    public Map<AppType, Long> packetsByApp() {
        Map<AppType, Long> stats = new LinkedHashMap<>();
        for (Flow f : table.values()) {
            stats.merge(f.getAppType(), (long) f.getPacketCount(), Long::sum);
        }
        return stats;
    }

    /** Unique SNIs seen */
    public Map<String, AppType> uniqueSnis() {
        Map<String, AppType> result = new LinkedHashMap<>();
        for (Flow f : table.values()) {
            if (!f.getSni().isBlank()) {
                result.putIfAbsent(f.getSni(), f.getAppType());
            }
        }
        return result;
    }
}
