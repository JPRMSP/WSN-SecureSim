import streamlit as st
import random
import networkx as nx
import plotly.graph_objects as go
import hashlib
import time
import json

st.set_page_config(page_title="WSN-SecureSim", layout="wide")

# ---------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------

def generate_nodes(n):
    nodes = {}
    for i in range(n):
        nodes[i] = {
            "x": random.randint(0, 100),
            "y": random.randint(0, 100),
            "energy": random.randint(60, 100),
            "trust": round(random.uniform(0.6, 1.0), 2),
            "address": None,
            "key": None,
        }
    return nodes

def plot_network(nodes, G, show_labels=False, chart_id="netplot"):
    fig = go.Figure()

    xs = [nodes[n]["x"] for n in nodes]
    ys = [nodes[n]["y"] for n in nodes]

    fig.add_trace(go.Scatter(
        x=xs,
        y=ys,
        mode="markers+text" if show_labels else "markers",
        text=[str(n) for n in nodes] if show_labels else None,
        marker=dict(size=12)
    ))

    for edge in G.edges():
        x0, y0 = nodes[edge[0]]["x"], nodes[edge[0]]["y"]
        x1, y1 = nodes[edge[1]]["x"], nodes[edge[1]]["y"]
        fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1],
                                 mode="lines", line=dict(width=1)))

    fig.update_layout(height=400, showlegend=False)
    st.plotly_chart(fig, use_container_width=True, key=f"{chart_id}_{random.randint(1,999999)}")

def hash_key(k):
    return hashlib.sha256(k.encode()).hexdigest()[:10]

# ---------------------------------------
# STREAMLIT UI
# ---------------------------------------

st.title("🔐 WSN-SecureSim — Advanced Integrated Edition")

mode = st.sidebar.selectbox(
    "Choose Simulation Module",
    ["Topology & Attacks", "Key Management", "Trust & Routing", "Data Aggregation", "Auto-Config (PDAA)", "Logs & Export"]
)

if "nodes" not in st.session_state:
    st.session_state.nodes = generate_nodes(12)
if "G" not in st.session_state:
    st.session_state.G = nx.random_geometric_graph(12, 0.35)
if "logs" not in st.session_state:
    st.session_state.logs = []


# ---------------------------------------------------------
# MODULE 1: TOPOLOGY & ATTACKS
# ---------------------------------------------------------
if mode == "Topology & Attacks":
    st.subheader("📡 WSN Topology Mapping & Attacks")

    st.info("Visualizing network with multiple attacks (jamming, Sybil, sinkhole, selective forwarding).")

    plot_network(st.session_state.nodes, st.session_state.G, show_labels=True, chart_id="topo")

    attack = st.selectbox("Choose an attack", ["Jamming", "Sybil", "Sinkhole", "Selective Forwarding"])

    if st.button("Simulate Attack"):
        st.session_state.logs.append(f"Attack executed: {attack}")
        st.success(f"{attack} attack simulated!")

# ---------------------------------------------------------
# MODULE 2: KEY MANAGEMENT (LEAP, PIKE, µTESLA)
# ---------------------------------------------------------
if mode == "Key Management":
    st.subheader("🔑 Key Management Protocols")

    proto = st.selectbox("Select protocol", ["LEAP", "PIKE", "µTESLA"])

    if proto == "LEAP":
        for n in st.session_state.nodes:
            st.session_state.nodes[n]["key"] = hash_key(str(n) + "_LEAP")
        st.success("LEAP Pairwise Keys Generated")
        st.json({n: st.session_state.nodes[n]["key"] for n in st.session_state.nodes})

    if proto == "PIKE":
        st.success("PIKE partial key graph constructed.")
        st.json({"PIKE Graph": "Simulated partial mesh key structure"})

    if proto == "µTESLA":
        st.success("µTESLA authentication schedule built.")
        st.write("Key Release Timeline:")
        st.json({f"t+{i}": hash_key(f"k{i}") for i in range(5)})

# ---------------------------------------------------------
# MODULE 3: TRUST & ROUTING (LEACH-TM, TRANS)
# ---------------------------------------------------------
if mode == "Trust & Routing":
    st.subheader("🔒 Trust-based Secure Routing")

    routing = st.selectbox("Choose routing protocol", ["LEACH-TM", "TRANS"])

    if routing == "LEACH-TM":
        for n in st.session_state.nodes:
            st.session_state.nodes[n]["trust"] = round(random.uniform(0.5, 1.0), 2)
        st.success("LEACH-TM trust weights updated.")
        st.json({n: st.session_state.nodes[n]["trust"] for n in st.session_state.nodes})

    if routing == "TRANS":
        ranked = sorted(st.session_state.nodes.items(), key=lambda x: x[1]["trust"], reverse=True)
        st.success("TRANS multi-criteria trusted nodes selected.")
        st.json(ranked[:5])

# ---------------------------------------------------------
# MODULE 4: DATA AGGREGATION (HSC-like, CDA)
# ---------------------------------------------------------
if mode == "Data Aggregation":
    st.subheader("📊 Secure Data Aggregation")

    agg = st.selectbox("Aggregation Method", ["CDA", "HSC-like", "Secure Hierarchical"])

    if agg == "CDA":
        val = [random.randint(10, 50) for _ in range(10)]
        cipher = [v * 7 for v in val]
        st.success("CDA (Ciphertext-domain) aggregation done.")
        st.json({"Raw": val, "Encrypted": cipher, "Sum": sum(cipher)})

    if agg == "HSC-like":
        val = [random.randint(10, 50) for _ in range(10)]
        st.success("Homomorphic-like aggregation performed.")
        st.json({"Sum (simulated homomorphic)": sum(val)})

    if agg == "Secure Hierarchical":
        st.success("Hierarchical multi-level aggregation simulated.")
        st.json({"Cluster 1": 120, "Cluster 2": 140, "Base Station": 260})

# ---------------------------------------------------------
# MODULE 5: PDAA (Address Assignment)
# ---------------------------------------------------------
if mode == "Auto-Config (PDAA)":
    st.subheader("🏷 PDAA — Distributed Address Assignment")

    if st.button("Assign Addresses"):
        used = set()
        for n in st.session_state.nodes:
            addr = random.randint(1, 255)
            while addr in used:
                addr = random.randint(1, 255)
            used.add(addr)
            st.session_state.nodes[n]["address"] = addr

        st.success("Unique addresses assigned using PDAA simulation.")
        st.json({n: st.session_state.nodes[n]["address"] for n in st.session_state.nodes})

    plot_network(st.session_state.nodes, st.session_state.G, show_labels=True, chart_id="pdaa")

# ---------------------------------------------------------
# MODULE 6: LOGS
# ---------------------------------------------------------
if mode == "Logs & Export":
    st.subheader("📜 Simulation Logs")
    st.write(st.session_state.logs)

    if st.button("Export Logs as JSON"):
        j = json.dumps(st.session_state.logs)
        st.download_button("Download", j, "logs.json")
