package au.org.ala.pac4j.oidc.statepool;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The serializable container placed in the pac4j {@code SessionStore} — the single session-stored
 * unit of state for the pool.
 *
 * <p>WARNING: {@code flowSecrets} was added after the v1 release with {@code serialVersionUID}
 * unchanged: a v1 byte stream deserializes with the field {@code null}, and
 * {@link #getFlowSecrets()} lazily upgrades it to an empty map. Do NOT bump
 * {@code serialVersionUID} for this addition.</p>
 */
public final class StatePoolHolder implements Serializable {

    /**
     * Not bumped when {@code flowSecrets} was added: the added field deserializes as
     * {@code null} from a v1 stream and is lazily re-created by {@link #getFlowSecrets()}.
     * Bump only for an incompatible shape change (field removal or type change).
     */
    private static final long serialVersionUID = 1L;

    /** state value &rarr; insertion epoch-millis, insertion-ordered; LRU ordering is applied by
     *  {@link SessionStatePoolStore} via remove-then-reinsert on every {@code add}. */
    private final LinkedHashMap<String, Long> entries;

    /** state value &rarr; per-flow secrets, insertion-ordered, swept/evicted on the same TTL/LRU
     *  schedule as {@link #entries}. An association SURVIVES consumption of its state (the
     *  callback needs the verifier/nonce after the state is spent) and dies only when its
     *  secrets are individually consumed or it ages out. Nullable ONLY transiently after
     *  deserializing a v1 byte stream. */
    private LinkedHashMap<String, FlowSecrets> flowSecrets;

    /**
     * Create a holder with no flow-secret associations (v1-compatible shape).
     */
    public StatePoolHolder(final Map<String, Long> entries) {
        this(entries, null);
    }

    /**
     * Create a holder from defensive copies of the given entries and associations.
     * {@code flowSecrets} may be {@code null}, treated as empty.
     */
    public StatePoolHolder(final Map<String, Long> entries, final Map<String, FlowSecrets> flowSecrets) {
        this.entries = new LinkedHashMap<>(entries);
        this.flowSecrets = flowSecrets == null ? new LinkedHashMap<>() : new LinkedHashMap<>(flowSecrets);
    }

    /** A copy of the entries. */
    public Map<String, Long> getEntries() {
        return new LinkedHashMap<>(entries);
    }

    /**
     * A copy of the flow-secret associations, keyed by state value. Lazily upgrades a
     * {@code null} field (v1-deserialized holder) to an empty map; never {@code null}.
     */
    public Map<String, FlowSecrets> getFlowSecrets() {
        if (flowSecrets == null) {
            // Reached only for a v1-serialized holder. Benign under a data race: the store
            // serializes real mutation under its per-session lock anyway.
            flowSecrets = new LinkedHashMap<>();
        }
        return new LinkedHashMap<>(flowSecrets);
    }
}
