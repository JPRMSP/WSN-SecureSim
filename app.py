import streamlit as st
import networkx as nx
import random
import math
import hashlib
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Tuple, List
import plotly.graph_objs as go

st.set_page_config(page_title="WSN-SecureSim - Advanced", layout="wide")

# -------------------------
# Helper dataclasses
# -------------------------
@dataclass
class Node:
    id: int
    pos: Tuple[float, float]
    trust: float = 1.0
    status: str = "normal"  # normal, jammed, sybil, dropper
    keys: Dict[str, str] = field(default_factory=dict)
    addr: int = None
    cluster: int = None

# -------------------------
# Topology & network init
# -------------------------
@st.cache_resource
def create_wsn(num_nodes=25, comm_radius=0.3, seed=42):
    random.seed(seed)
    nodes = {}
    G = nx.Graph()
    for i in range(num_nodes):
        x, y = random.random(), random.random()
        nodes[i] = Node(id=i, pos=(x, y))
        G.add_node(i, pos=(x, y))
    # add edges based on geometric range
    for i in nodes:
        for j in nodes:
            if i < j:
                xi, yi = nodes[i].pos
                xj, yj = nodes[j].pos
                d = math.hypot(xi - xj, yi - yj)
                if d <= comm_radius:
                    G.add_edge(i, j)
    # initial addresses
    for i in nodes:
        nodes[i].addr = i + 1000  # base addresses
    return nodes, G

# -------------------------
# Visualization helpers
# -------------------------
def plot_network(nodes: Dict[int, Node], G: nx.Graph, highlight_nodes: List[int]=None, show_labels=True, show_clusters=False):
    highlight_nodes = highlight_nodes or []
    edge_x = []
    edge_y = []
    for e in G.edges():
        x0, y0 = nodes[e[0]].pos
        x1, y1 = nodes[e[1]].pos
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    node_x = []
    node_y = []
    text = []
    marker_color = []
    marker_size = []
    for n in G.nodes():
        x, y = nodes[n].pos
        node_x.append(x)
        node_y.append(y)
        text.append(f"Node {n} | T:{nodes[n].trust:.2f} | {nodes[n].status} | addr:{nodes[n].addr}")
        color = "green"
        if nodes[n].status != "normal":
            color = "red"
        if n in highlight_nodes:
            color = "orange"
        if show_clusters and nodes[n].cluster is not None:
            # derive color from cluster id
            color = f"hsl({(nodes[n].cluster * 47) % 360},70%,40%)"
        marker_color.append(color)
        marker_size.append(12 if nodes[n].status == "normal" else 16)

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#888'),
        hoverinfo='none',
        mode='lines'
    )

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text' if show_labels else 'markers',
        hoverinfo='text',
        text=[f"{n}" for n in G.nodes()] if show_labels else None,
        marker=dict(
            showscale=False,
            color=marker_color,
            size=marker_size,
            line_width=1
        ),
        textposition="top center",
        textfont=dict(size=9)
    )
    node_trace.text = text if show_labels else None

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        showlegend=False,
                        margin=dict(b=20,l=5,r=5,t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        height=600
                    ))
    st.plotly_chart(fig, use_container_width=True)

# -------------------------
# Attacks & IDS
# -------------------------
def launch_attack(nodes: Dict[int, Node], G: nx.Graph, attack_type: str, intensity=0.3):
    affected = []
    if attack_type == "Jamming":
        # pick a region center and jam nearby nodes
        center = (random.random(), random.random())
        for n, obj in nodes.items():
            d = math.hypot(obj.pos[0] - center[0], obj.pos[1] - center[1])
            if d < intensity:
                obj.status = "jammed"
                affected.append(n)
    elif attack_type == "Sybil":
        # create fake identities at one attacker node
        attacker = random.choice(list(nodes.keys()))
        nodes[attacker].status = "sybil"
        affected.append(attacker)
    elif attack_type == "Selective Forwarding":
        # random set of droppers
        for n in random.sample(list(nodes.keys()), k=max(1, int(len(nodes)*intensity))):
            nodes[n].status = "dropper"
            affected.append(n)
    elif attack_type == "Hello Flood":
        # mark some nodes as "hello_flood" victims (their routing tables confused)
        for n in random.sample(list(nodes.keys()), k=max(1, int(len(nodes)*intensity))):
            nodes[n].status = "hello_flood"
            affected.append(n)
    return affected

def simple_ids(nodes: Dict[int, Node]):
    alerts = []
    for n, obj in nodes.items():
        if obj.status != "normal":
            alerts.append((n, obj.status))
    return alerts

# -------------------------
# Key Management Simulators
# -------------------------
# LEAP-like: per-node individual key + pairwise key derived from master
MASTER_KEY = secrets.token_hex(16)

def leap_assign(nodes: Dict[int, Node]):
    for n, obj in nodes.items():
        # each node gets an individual key (simulated) derived from MASTER_KEY and id
        obj.keys['individual'] = hashlib.sha256((MASTER_KEY + str(n)).encode()).hexdigest()
    # pairwise: derive pairwise key on demand using both individual keys (symmetric)
    return True

def get_pairwise_key(nodes: Dict[int, Node], a: int, b: int):
    # symmetric: hash(individual_a || individual_b) truncated
    ka = nodes[a].keys.get('individual')
    kb = nodes[b].keys.get('individual')
    if not ka or not kb:
        return None
    digest = hashlib.sha256((ka + kb).encode()).hexdigest()
    return digest[:32]

# PIKE-like: grid-based pairwise (simulate using buckets)
def pike_assign(nodes: Dict[int, Node], grid_size=4):
    # place nodes into grid cells and set a shared key per row/col
    buckets = defaultdict(list)
    for n, obj in nodes.items():
        gx = int(obj.pos[0] * grid_size)
        gy = int(obj.pos[1] * grid_size)
        buckets[(gx, gy)].append(n)
    # generate bucket keys
    bucket_keys = {}
    for b in buckets:
        bucket_keys[b] = secrets.token_hex(8)
    # assign PIKE keys as combination of neighboring buckets
    for n, obj in nodes.items():
        gx = int(obj.pos[0] * grid_size)
        gy = int(obj.pos[1] * grid_size)
        obj.keys['pike'] = bucket_keys[(gx, gy)]
    return buckets

# µTESLA: hash chain generation and schedule
class MuTesla:
    def __init__(self, chain_len=20):
        self.chain_len = chain_len
        self.keys = [secrets.token_hex(8) for _ in range(chain_len)]
        self.hash_chain = [None] * chain_len
        # build hash chain: K_i -> H(K_i) ... final anchor = H^n(K_n)
        self.hash_chain[-1] = hashlib.sha256(self.keys[-1].encode()).hexdigest()
        for i in range(chain_len-2, -1, -1):
            self.hash_chain[i] = hashlib.sha256(self.keys[i].encode()).hexdigest() + self.hash_chain[i+1][:6]  # mix
        self.anchor = self.hash_chain[0]
        self.current_index = 0

    def disclose_next(self):
        if self.current_index < self.chain_len:
            k = self.keys[self.current_index]
            idx = self.current_index
            self.current_index += 1
            return idx, k
        else:
            return None, None

    def verify(self, idx, key):
        # simple verification: recompute hash and compare partial
        h = hashlib.sha256(key.encode()).hexdigest()
        return h.startswith(self.hash_chain[idx][:6])

# -------------------------
# Trust models: LEACH-TM & TRANS
# -------------------------
def update_trust_behavior(nodes: Dict[int, Node], decay=0.05, reward=0.02):
    # behavioral: normal nodes gain small trust, misbehaving lose larger trust
    for n, obj in nodes.items():
        if obj.status == "normal":
            obj.trust = min(1.0, obj.trust + reward)
        else:
            obj.trust = max(0.0, obj.trust - decay)

def leach_tm_cluster(nodes: Dict[int, Node], G: nx.Graph, k=4):
    # choose k cluster heads using trust-weighted probability
    node_list = list(nodes.keys())
    trust_vals = [nodes[n].trust for n in node_list]
    # higher trust -> higher chance
    total = sum(trust_vals) if sum(trust_vals) > 0 else 1
    probs = [t/total for t in trust_vals]
    chosen = set()
    while len(chosen) < min(k, len(node_list)):
        pick = random.choices(node_list, weights=probs, k=1)[0]
        chosen.add(pick)
    # assign cluster id to nodes based on nearest CH
    for n in nodes:
        best = None
        bestd = 10
        for i, ch in enumerate(chosen):
            d = math.hypot(nodes[n].pos[0] - nodes[ch].pos[0], nodes[n].pos[1] - nodes[ch].pos[1])
            if d < bestd:
                bestd = d
                best = ch
        nodes[n].cluster = list(chosen).index(best)
    return list(chosen)

def trans_trust_score(nodes: Dict[int, Node], energy_map: Dict[int,float]=None):
    # multi-criteria: reliability (behavioral trust), energy (simulated), connectivity degree
    energy_map = energy_map or {n: random.uniform(0.4, 1.0) for n in nodes}
    scores = {}
    for n, obj in nodes.items():
        reliability = obj.trust
        energy = energy_map.get(n, 0.5)
        degree = max(1, random.randint(1, 10))
        # weighted sum
        score = 0.6*reliability + 0.3*energy + 0.1*(degree/10)
        scores[n] = score
    return scores

# -------------------------
# Data aggregation: plaintext & HSC-like
# -------------------------
def plaintext_aggregate(nodes: Dict[int, Node]):
    vals = {n: random.randint(1, 100) for n in nodes}
    return vals, sum(vals.values())

def hsc_masked_aggregate(nodes: Dict[int, Node], ch_list: List[int]):
    # Simulate homomorphic-like masked aggregation:
    # each node adds a random mask; CH sums masked vals and subtracts known masks from legitimate nodes.
    vals = {n: random.randint(1, 100) for n in nodes}
    masks = {n: secrets.randbelow(256) for n in nodes}
    masked = {n: vals[n] + masks[n] for n in nodes}
    # at CH, aggregate masked
    agg_masked = sum(masked.values())
    # CH obtains masks from nodes in its cluster only (simulate secure disclosure)
    # For demo, assume all masks are disclosed to legitimate CHs and aggregator recovers sum
    recovered = agg_masked - sum(masks.values())
    return vals, masks, masked, agg_masked, recovered

# -------------------------
# PDAA - dynamic address allocation (simplified)
# -------------------------
def pdaa_allocate(nodes: Dict[int, Node], G: nx.Graph, start_addr=2000):
    # leaderless distributed allocation: nodes pick random candidate addresses and resolve conflicts by ID
    candidate = {}
    for n, obj in nodes.items():
        candidate[n] = start_addr + random.randint(0, 500)
    # conflict resolution: if two nodes pick same addr, higher-id keeps lower addr
    addr_map = {}
    inv = defaultdict(list)
    for n, a in candidate.items():
        inv[a].append(n)
    for a, owners in inv.items():
        if len(owners) == 1:
            addr_map[owners[0]] = a
        else:
            # sort owners: lower node id gets bumped to next free addr
            owners_sorted = sorted(owners)
            taken = a
            for owner in owners_sorted:
                # find next free
                while taken in addr_map.values():
                    taken += 1
                addr_map[owner] = taken
    # apply
    for n in nodes:
        nodes[n].addr = addr_map[n]
    return addr_map

# -------------------------
# Utilities
# -------------------------
def reset_status(nodes: Dict[int, Node]):
    for n in nodes:
        nodes[n].status = "normal"
        nodes[n].trust = 1.0
        nodes[n].cluster = None

# -------------------------
# UI layout
# -------------------------
st.title("🔐 WSN-SecureSim — Advanced Integrated Edition")
st.markdown("**Syllabus-mapped features:** LEAP, PIKE, µTESLA, LEACH-TM, TRANS, HSC-like aggregation, PDAA. "
            "Simulation-only, interactive visualization, no datasets/models.")

# Sidebar controls
st.sidebar.header("Simulation Controls")
num_nodes = st.sidebar.slider("Number of nodes", min_value=8, max_value=60, value=25, step=1)
comm_radius = st.sidebar.slider("Communication radius (relative)", 0.1, 0.6, 0.3, 0.05)
seed = st.sidebar.number_input("Random seed", value=42, step=1)

if 'nodes' not in st.session_state or st.session_state.get('num_nodes') != num_nodes or st.session_state.get('comm_radius') != comm_radius or st.session_state.get('seed') != seed:
    st.session_state['nodes'], st.session_state['G'] = create_wsn(num_nodes=num_nodes, comm_radius=comm_radius, seed=seed)
    st.session_state['num_nodes'] = num_nodes
    st.session_state['comm_radius'] = comm_radius
    st.session_state['seed'] = seed
    reset_status(st.session_state['nodes'])
    leap_assign(st.session_state['nodes'])
    pike_assign(st.session_state['nodes'])
    st.session_state['mut'] = MuTesla(chain_len=16)
    st.session_state['logs'] = []

nodes = st.session_state['nodes']
G = st.session_state['G']
mut = st.session_state['mut']

# Main tabs
tabs = st.tabs(["Topology & Attacks", "Key Management", "Trust & Routing", "Data Aggregation", "Auto-Config (PDAA)", "Logs & Export"])

# ---------- Tab 1: Topology & Attacks ----------
with tabs[0]:
    st.header("Topology & Attacks")
    c1, c2 = st.columns([2,1])
    with c2:
        st.subheader("Attack Panel")
        attack_type = st.selectbox("Select attack", ["None", "Jamming", "Sybil", "Selective Forwarding", "Hello Flood"])
        intensity = st.slider("Attack intensity", 0.05, 0.6, 0.25)
        if st.button("Launch Attack"):
            if attack_type != "None":
                affected = launch_attack(nodes, G, attack_type, intensity=intensity)
                st.session_state['logs'].append(f"Attack launched: {attack_type} affected {len(affected)} nodes")
                st.success(f"Launched {attack_type} — affected nodes: {affected[:8]}{'...' if len(affected)>8 else ''}")
            else:
                st.info("No attack chosen.")
        if st.button("Reset Status"):
            reset_status(nodes)
            st.session_state['logs'].append("Status reset")
            st.experimental_rerun()
        st.subheader("Intrusion Detection")
        if st.button("Run IDS"):
            alerts = simple_ids(nodes)
            if alerts:
                for a in alerts:
                    st.error(f"IDS Alert — Node {a[0]}: {a[1]}")
                st.session_state['logs'].append(f"IDS raised {len(alerts)} alerts")
            else:
                st.success("No alerts")

    with c1:
        st.subheader("Network View")
        plot_network(nodes, G, show_labels=True)

# ---------- Tab 2: Key Management ----------
with tabs[1]:
    st.header("Key Management (LEAP, PIKE, µTESLA simulated)")
    st.markdown("This panel demonstrates how LEAP assigns per-node keys, PIKE per-bucket keys, and µTESLA hash-chain disclosure.")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("LEAP")
        if st.button("Assign LEAP keys (recompute)"):
            leap_assign(nodes)
            st.session_state['logs'].append("LEAP keys (individual) assigned")
            st.success("LEAP: individual keys assigned to all nodes")
        a = st.number_input("Inspect pairwise key: node A", min_value=0, max_value=num_nodes-1, value=0)
        b = st.number_input("Inspect pairwise key: node B", min_value=0, max_value=num_nodes-1, value=1)
        if st.button("Show pairwise key"):
            pk = get_pairwise_key(nodes, int(a), int(b))
            st.code(f"Pairwise key between {a} and {b}: {pk}")

    with col2:
        st.subheader("PIKE")
        grid_size = st.slider("PIKE grid size", 2, 8, 4)
        if st.button("Assign PIKE buckets"):
            buckets = pike_assign(nodes, grid_size=grid_size)
            st.session_state['logs'].append(f"PIKE buckets assigned with grid {grid_size}")
            st.success(f"PIKE assigned into {len(buckets)} buckets")
        if st.button("Show node PIKE keys (first 6)"):
            example = {n: nodes[n].keys.get('pike') for n in list(nodes)[:6]}
            st.json(example)

    st.subheader("µTESLA broadcast authentication")
    if st.button("Disclose next µTESLA key"):
        idx, k = mut.disclose_next()
        if idx is not None:
            verified = mut.verify(idx, k)
            st.session_state['logs'].append(f"µTESLA disclosed index {idx} key (verified={verified})")
            st.write(f"Disclosed index {idx} key: {k} — verification: {verified}")
        else:
            st.info("No more keys to disclose")
    st.write("Anchor (public):")
    st.code(mut.anchor)

# ---------- Tab 3: Trust & Routing ----------
with tabs[2]:
    st.header("Trust, LEACH-TM clustering & TRANS scoring")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Behavioral trust update")
        if st.button("Run behavior update"):
            update_trust_behavior(nodes)
            st.session_state['logs'].append("Behavioral trust updated")
            st.success("Trust values updated using behavior model")
        st.write("Trust table (first 20 nodes):")
        ttable = {n: round(nodes[n].trust, 3) for n in list(nodes)[:min(20,len(nodes))]}
        st.json(ttable)

    with col2:
        st.subheader("LEACH-TM clustering (trust-aware CH selection)")
        kchs = st.slider("Number of cluster heads", 1, min(8, num_nodes), 4)
        if st.button("Run LEACH-TM clustering"):
            chs = leach_tm_cluster(nodes, G, k=kchs)
            st.session_state['logs'].append(f"LEACH-TM cluster heads: {chs}")
            st.success(f"Selected CHs: {chs}")
            plot_network(nodes, G, show_clusters=True)
        st.subheader("TRANS multi-criteria trust scores")
        if st.button("Compute TRANS scores"):
            scores = trans_trust_score(nodes)
            top = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:8]
            st.write("Top TRANS scores (node:score):")
            st.json({n:round(s,3) for n,s in top})
            st.session_state['logs'].append("TRANS scores computed")

# ---------- Tab 4: Data Aggregation ----------
with tabs[3]:
    st.header("Data Aggregation (Plaintext & HSC-like masked)")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Plaintext aggregation")
        if st.button("Run plaintext aggregation"):
            vals, total = plaintext_aggregate(nodes)
            st.session_state['logs'].append(f"Plaintext aggregated total: {total}")
            st.write("Sample values (first 8):")
            st.json({n: vals[n] for n in list(vals)[:8]})
            st.success(f"Aggregated total: {total}")

    with col2:
        st.subheader("HSC-like masked aggregation")
        if st.button("Run masked aggregation"):
            ch_list = [n for n in nodes if nodes[n].cluster is not None]
            vals, masks, masked, masked_sum, recovered = hsc_masked_aggregate(nodes, ch_list)
            st.session_state['logs'].append(f"HSC masked aggregated masked_sum:{masked_sum} recovered:{recovered}")
            st.write("Recovered aggregated value (after mask removal):", recovered)
            st.write("Masked example (first 6):")
            ex = {n: masked[n] for n in list(masked)[:6]}
            st.json(ex)
            st.success("Masked aggregation simulated")

# ---------- Tab 5: Auto-Configuration (PDAA) ----------
with tabs[4]:
    st.header("PDAA — Preemptive Distributed Address Assignment (simulated)")
    if st.button("Run PDAA allocation"):
        addr_map = pdaa_allocate(nodes, G, start_addr=3000)
        st.session_state['logs'].append("PDAA addresses assigned")
        st.write("Assigned addresses (first 12):")
        st.json({n: addr_map[n] for n in list(addr_map)[:12]})
        st.success("PDAA allocation complete")
    if st.button("Show network with addresses"):
        plot_network(nodes, G, show_labels=True)

# ---------- Tab 6: Logs & Export ----------
with tabs[5]:
    st.header("Simulation Logs & Export")
    logs = st.session_state.get('logs', [])
    st.write("Event log (latest 50):")
    for l in logs[-50:]:
        st.text(f"- {l}")
    st.markdown("---")
    st.subheader("Export snapshot (JSON-like)")
    if st.button("Export snapshot (display)"):
        snapshot = {
            'nodes': {n: {'addr': nodes[n].addr, 'trust': nodes[n].trust, 'status': nodes[n].status, 'keys': list(nodes[n].keys.keys()), 'cluster': nodes[n].cluster} for n in nodes},
            'edges': list(G.edges()),
            'mut_anchor': mut.anchor
        }
        st.json(snapshot)
        st.session_state['logs'].append("Snapshot exported (display)")

st.markdown("---")
st.info("Notes: This is a simulation environment aligning academic protocol ideas with interactive demos. "
        "It intentionally simplifies cryptographic operations for clarity (do not use for production crypto!).")

# Footer: quick tips
st.caption("Tips: Use the tabs left-to-right to simulate an attack, assign keys, run IDS, compute trust & clusters, aggregate data, and try PDAA address allocation. All modules are integrated for classroom demo.")
