# DSDN_SmartGridLab

A hands-on lab module for the [MizzouCloudDevops](https://www.mizzouclouddevops.net/) platform at the University of Missouri.

This lab deploys a **Distributed Software Defined Networking (D-SDN)** architecture using a 3-node ONOS cluster with Atomix on AWS EC2, emulates a smart grid SCADA network with 24 DNP3 hosts via Mininet, simulates a **Master Impersonation attack** using Scapy IP spoofing, and defends against it using **GridCAD** - an AI-powered detection and response pipeline built on phi4-mini (via Ollama), ChromaDB RAG, and automated ONOS flow rule deployment.

---

## Repository Structure

```
DSDN_SmartGridLab/
├── dnp3_scripts/
│   ├── simple_master.py          # DNP3 master station (polls outstations 2-24)
│   └── simple_outstation.py      # DNP3 outstation (responds to master)
├── attack_det_mit.py             # GridCAD: unified detector + LLM policy engine
├── attack_simulation.py          # Master Impersonation attack (Scapy IP spoofing)
├── dnp3_setup.sh                 # Python 3.10 + dnp3-python installation
├── llm_setup.sh                  # Ollama + phi4-mini + RAG (CPU)
├── llm_setupwith_gpu.sh          # Ollama + phi4-mini + RAG (GPU, g5.xlarge)
├── mininet_setup.sh              # Mininet + Open vSwitch installation
├── onos_cluster_setup.sh         # 3-node ONOS cluster + Atomix Docker deployment
├── topology_setup.py             # Mininet 24-host smart grid topology
├── tshark_setup.sh               # Tshark + Scapy installation
└── README.md
```

## Setup Order

Run the scripts in the following order. Each script is idempotent and self-validating.

### Step 1 — Clone the Repository

```bash
cd ~
git clone https://github.com/harshavardhanchintapatla/DSDN_SmartGridLab
cd DSDN_SmartGridLab
```

### Step 2 — Deploy ONOS Cluster (Chapter 3)

Deploys 3 ONOS controllers and 3 Atomix nodes as Docker containers on a private bridge network.

```bash
chmod +x onos_cluster_setup.sh
./onos_cluster_setup.sh
```

After completion, access the ONOS Web UI at `http://<YOUR-EC2-IP>:8181/onos/ui` (username: `onos`, password: `rocks`) and verify all 3 cluster nodes show green checkmarks under **Cluster Nodes**.

### Step 3 — Install Mininet (Chapter 3)

```bash
chmod +x mininet_setup.sh
./mininet_setup.sh
```

### Step 4 — Install DNP3 Environment (Chapter 4)

Installs Python 3.10 and the `dnp3-python` library in an isolated virtual environment at `~/dnp3_310`.

```bash
chmod +x dnp3_setup.sh
./dnp3_setup.sh
```

### Step 5 — Install Tshark and Scapy (Chapter 4)

```bash
chmod +x tshark_setup.sh
./tshark_setup.sh
```

### Step 6 — Install Ollama, phi4-mini, and RAG Environment (Chapter 4)

Use `llm_setup.sh` for CPU-only instances or `llm_setupwith_gpu.sh` for GPU instances (g5.xlarge recommended).

```bash
chmod +x llm_setup.sh
./llm_setup.sh
```

Verify installation:

```bash
ollama list
OLLAMA_DEBUG=1 ollama run phi4-mini 'test'
source ~/gridcad_env/bin/activate
python3 -c "import chromadb; import sentence_transformers; print('RAG OK')"
deactivate
```

---

## Running the Lab (Chapter 4 and 5)

### Terminal 1 — Start Smart Grid Topology

Launches a 24-host Mininet topology with 12 OpenFlow switches distributed across 3 ONOS controllers. DNP3 master and outstations start automatically.

```bash
sudo python3 topology_setup.py
```

Topology summary:
- `h1` (10.0.0.1) — DNP3 Master station
- `h2`–`h24` (10.0.0.2–10.0.0.24) — DNP3 Outstations
- `s1`–`s4` managed by `c1` (172.20.0.5)
- `s5`–`s8` managed by `c2` (172.20.0.6)
- `s9`–`s12` managed by `c3` (172.20.0.7)

Test connectivity:
```bash
mininet> pingall
```

### Terminal 2 — Monitor DNP3 Traffic (optional)

```bash
sudo tshark -l -i any -f 'tcp portrange 20002-20024' \
  -d tcp.port==20002,dnp3 -d tcp.port==20003,dnp3 -d tcp.port==20004,dnp3 \
  -d tcp.port==20005,dnp3 -d tcp.port==20006,dnp3 -d tcp.port==20007,dnp3 \
  -d tcp.port==20008,dnp3 -d tcp.port==20009,dnp3 -d tcp.port==20010,dnp3 \
  -d tcp.port==20011,dnp3 -d tcp.port==20012,dnp3 -d tcp.port==20013,dnp3 \
  -d tcp.port==20014,dnp3 -d tcp.port==20015,dnp3 -d tcp.port==20016,dnp3 \
  -d tcp.port==20017,dnp3 -d tcp.port==20018,dnp3 -d tcp.port==20019,dnp3 \
  -d tcp.port==20020,dnp3 -d tcp.port==20021,dnp3 -d tcp.port==20022,dnp3 \
  -d tcp.port==20023,dnp3 -d tcp.port==20024,dnp3 \
  -Y 'dnp3' \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e dnp3.al.func -e dnp3.al.seq -e dnp3.al.iin -e dnp3.al.uns
```

Press **Ctrl+C** to stop before starting GridCAD, as GridCAD runs its own internal Tshark processes.

### Terminal 3 — Start GridCAD (Chapter 5)

```bash
source ~/gridcad_env/bin/activate
python3 /home/ubuntu/DSDN_SmartGridLab/attack_det_mit.py --onos-ip 172.20.0.5 --enable-llm
```

### Terminal 1 — Simulate Master Impersonation Attack (Chapter 5)

From the Mininet CLI, run the attack script. It uses Scapy to craft a raw DNP3 packet with the source IP forged to `10.0.0.1` (the master station).

```bash
mininet> h6 python3 /home/ubuntu/DSDN_SmartGridLab/attack_simulation.py \
    --attacker-station 6 --victim-station 24 --fc 13 --count 1 --debug
```

GridCAD will detect the topology violation, generate a `PORT_BLOCK_SPOOF` ONOS flow rule via phi4-mini, and deploy it automatically.

### Terminal 4 — Verify Deployed Flow Rule (Chapter 5)

```bash
curl -u onos:rocks http://172.20.0.5:8181/onos/v1/flows | \
    jq '.flows[] | select(.appId=="org.onosproject.llm")'
```

---

## Script Reference

### `onos_cluster_setup.sh`

Deploys a 3-node ONOS 2.2.1 cluster with 3 Atomix 3.1.5 nodes as Docker containers on a private `172.20.0.0/16` bridge network. Auto-detects the EC2 public IP if not set manually. Generates all Atomix and ONOS cluster config files, waits for REST API readiness on ports 8181–8183, and prints Web UI URLs on completion.

### `mininet_setup.sh`

Installs Mininet and Open vSwitch on Ubuntu 24.04. Enables the `openvswitch-switch` service, cleans any previous Mininet state, and verifies the `mn` command.

### `dnp3_setup.sh`

Installs Python 3.10 via the deadsnakes PPA and creates an isolated virtual environment at `~/dnp3_310`. Installs the `dnp3-python` package and verifies it by importing master and outstation classes.

### `tshark_setup.sh`

Installs `tshark`, `tcpdump`, `jq`, and `python3-scapy`. Configures Wireshark for non-root packet capture and adds the current user to the `wireshark` group. Falls back to `pip3 install scapy` if the apt package is incomplete.

### `llm_setup.sh` / `llm_setupwith_gpu.sh`

Installs Ollama and downloads the `phi4-mini` model (~2.5 GB). Creates the `~/gridcad_env` Python virtual environment with ChromaDB, sentence-transformers, PyTorch (CPU build to avoid pulling the 3 GB CUDA build), and the Ollama Python client. Installs `ollama` and `requests` system-wide for `sudo` execution of detection scripts.

### `topology_setup.py`

Creates a Mininet topology with 24 hosts, 12 OpenFlow 1.3 switches, and 3 remote ONOS controllers. Intra-group connectivity uses a mini-star pattern (s1 connects s2/s3/s4, s5 connects s6/s7/s8, s9 connects s10/s11/s12). Inter-group mesh connects s1-s5-s9-s1. Automatically starts DNP3 outstations on h2–h24 and the master on h1 on launch.

### `dnp3_scripts/simple_outstation.py`

Runs a DNP3 outstation using the `dnp3-python` library. Accepts `--station-id` (2–24) and `--base-port` (default 20000). Listens on port `20000 + station_id` and responds to master polling requests.

### `dnp3_scripts/simple_master.py`

Runs a DNP3 master that connects to and polls multiple outstations on a configurable interval. Accepts `--stations` (list of station IDs, default 2–24) and `--poll-interval` (default 15 seconds). Sends `scan_all_request` to each outstation sequentially.

### `attack_simulation.py`

Uses Scapy raw sockets to craft DNP3 packets with the source IP forged to `10.0.0.1` (master), simulating a Master Impersonation attack. Accepts `--attacker-station`, `--victim-station`, `--fc` (13, 14, 18, or 21), `--count`, and `--debug`. Also supports a `--campaign` mode for running a full evaluation matrix across multiple victims and function codes.

### `attack_det_mit.py`

GridCAD unified detection and response pipeline. Runs two background Tshark threads (raw TCP payload capture and decoded DNP3 function code capture). Detects Master Impersonation attacks via topology ingress port validation. When `--enable-llm` is set, feeds structured attack intelligence to phi4-mini via Ollama alongside RAG context retrieved from ChromaDB, receives a policy blueprint, validates it through a deterministic safety gate, and deploys ONOS flow rules via the REST API. Writes a full audit log (`audit_log.jsonl`) for every alert.

**Key flags:**
```
--onos-ip         ONOS controller IP (default: 172.20.0.5)
--enable-llm      Enable phi4-mini LLM policy engine
--llm-model       Model name (default: phi4-mini)
--rag-mode        full | seed_only | disabled (default: full)
--safety-mode     enabled | disabled (default: enabled)
--experiment-mode Sets block expiry to 15s for rapid re-attack testing
--audit-log       Path for JSONL audit log (default: ./audit_log.jsonl)
```

---

## GridCAD Pipeline Overview

```
DNP3 Traffic (Tshark)
        |
        v
Attack Detection (topology ingress port mismatch)
        |
        v
RAG Context Retrieval (ChromaDB + sentence-transformers)
        |
        v
LLM Policy Synthesis (phi4-mini via Ollama)
        |
        v
Safety Validation (deterministic structural rules)
        |
        v
ONOS Flow Rule Deployment (REST API)
        |
        v
Explainability Narrative (phi4-mini Pass 2, async)
```

## Shut Down

```bash
# Terminal 3 — stop GridCAD
Ctrl+C

# Terminal 1 — stop Mininet
mininet> exit

# Any terminal — stop all Docker containers
sudo docker stop onos-1 onos-2 onos-3 atomix-1 atomix-2 atomix-3
```

## References

- [ONOS SDN Controller](https://wiki.onosproject.org/)
- [Atomix Distributed Coordination](https://wiki.onosproject.org/display/ONOS/Atomix)
- [Ollama — Local LLM Inference](https://ollama.com/)
- [phi4-mini Model](https://ollama.com/library/phi4-mini)
- [ChromaDB Vector Database](https://docs.trychroma.com/)
- [Sentence Transformers](https://www.sbert.net/)
- [DNP3 Protocol Specification](https://www.dnp.org/About/Overview-of-DNP3-Protocol)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [Mininet Network Emulator](http://mininet.org/)
