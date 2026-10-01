#!/usr/bin/env python3
"""A Knots regtest node validates the JXL-n-hide transaction shape under the
BLAKE2b flag day rules (RDTS/BIP110 active) with the Knots default relay
policy on.  The transaction reaches the node over P2P, as it does on mainnet,
and the node's memory is searched for the image at three points:

  1. after the node has accepted it to the mempool, before any RPC that
     serializes it has run;
  2. after a peer has fetched the transaction with getdata;
  3. after the block holding it has been mined and a peer has fetched the block.

The 25 witness scripts are the mainnet ones from
23e8f9466cd895c21a041155dba377f1a77a46cec13dcb14c430fa9c75f8786a (block 969961).
The raw transaction is fetched from mempool.guide on first run and cached as tx.bin.

Run from a Bitcoin Knots source tree with a build (BITCOIND may point at another binary):
    PYTHONPATH=<knots>/test/functional python3 ram_demo.py --configfile <knots>/build/test/config.ini
Needs djxl from libjxl-tools for the final render.
"""
import hashlib, os, re, struct, subprocess, urllib.request
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness, CInv,
                                     msg_tx, msg_getdata, MSG_WTX, MSG_BLOCK, MSG_WITNESS_FLAG)
from test_framework.p2p import P2PInterface
from test_framework.script import CScript
from test_framework.wallet import MiniWallet

HERE = os.path.dirname(os.path.abspath(__file__))
TXID = '23e8f9466cd895c21a041155dba377f1a77a46cec13dcb14c430fa9c75f8786a'
SIG = bytes.fromhex('0000000c4a584c200d0a870a')  # JPEG XL container signature box
IMG_LEN = 37975

def fetch_tx():
    path = os.path.join(HERE, 'tx.bin')
    if not os.path.exists(path):
        hexdata = urllib.request.urlopen(f'https://mempool.guide/api/tx/{TXID}/hex').read().strip()
        open(path, 'wb').write(bytes.fromhex(hexdata.decode()))
    return open(path, 'rb').read()

def compact(b, p):
    n = b[p]
    if n < 0xfd: return n, p + 1
    if n == 0xfd: return struct.unpack_from('<H', b, p + 1)[0], p + 3
    if n == 0xfe: return struct.unpack_from('<I', b, p + 1)[0], p + 5
    return struct.unpack_from('<Q', b, p + 1)[0], p + 9

def mainnet_witness_scripts(raw):
    p = 6
    nin, p = compact(raw, p)
    for _ in range(nin):
        p += 36; l, p = compact(raw, p); p += l + 4
    nout, p = compact(raw, p)
    for _ in range(nout):
        p += 8; l, p = compact(raw, p); p += l
    scripts = []
    for _ in range(nin):
        cnt, p = compact(raw, p)
        items = []
        for _ in range(cnt):
            l, p = compact(raw, p); items.append(raw[p:p + l]); p += l
        assert len(items) == 1
        scripts.append(items[0])
    return scripts

def p2wsh(script):
    return CScript(bytes([0x00, 0x20]) + hashlib.sha256(script).digest())

def dead_branch_script(push_len):
    data = (bytes(range(256)) * (push_len // 256 + 1))[:push_len]
    return b'\x51\x64' + b'\x4d' + struct.pack('<H', push_len) + data + b'\x68\x51'

class QuietPeer(P2PInterface):
    """A peer that never answers an inv with getdata, so the node serializes
    nothing for it unless this script asks.  It keeps every byte the node
    sends it, as it came off the socket."""
    def __init__(self):
        super().__init__()
        self.raw = b''
    def on_inv(self, message):
        pass
    def data_received(self, t):
        self.raw += bytes(t)
        super().data_received(t)

class RamDemo(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Fork at 100 with a far expiry: every block after the warmup is under RDTS.
        # -corepolicy=0 restores the Knots default relay policy the framework turns off.
        self.extra_args = [['-testactivationheight=blake2b@100', '-rdtsexpiry=2000000000', '-corepolicy=0']]

    def scan_memory(self, pid, needles):
        """Return {name: [addresses]} of every occurrence of each needle in the
        writable mappings of pid, and the number of bytes scanned."""
        hits = {name: [] for name in needles}
        maps = open(f'/proc/{pid}/maps').read().splitlines()
        fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
        scanned = 0
        longest = max(len(n) for n in needles.values())
        for line in maps:
            m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S+)', line)
            lo, hi, perms = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
            if not perms.startswith('rw'): continue
            if '[vvar]' in line or '[vsyscall]' in line: continue
            pos = lo
            tail = b''
            while pos < hi:
                n = min(8 << 20, hi - pos)
                try:
                    chunk = os.pread(fd, n, pos)
                except OSError:
                    break
                buf = tail + chunk
                base = pos - len(tail)
                for name, needle in needles.items():
                    i = buf.find(needle)
                    while i != -1:
                        addr = base + i
                        if addr not in hits[name]:
                            hits[name].append(addr)
                        i = buf.find(needle, i + 1)
                tail = buf[-longest:]
                scanned += len(chunk)
                pos += n
        os.close(fd)
        return hits, scanned

    def report(self, label, pid, scripts, img):
        """Scan the node's memory and log how many whole witness scripts and
        whole-file copies it holds right now.  Returns the whole-file addresses."""
        hits, scanned = self.scan_memory(pid, {'jxl': SIG, 'script0': scripts[0]})
        fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
        full = [a for a in hits['jxl'] if os.pread(fd, IMG_LEN, a) == img]
        os.close(fd)
        inside = [a for a in hits["script0"] if any(f - 8 <= a < f + IMG_LEN for f in full)]  # script #1 starts 4 bytes before the file
        alone = len(hits['script0']) - len(inside)
        self.log.info(f'[{label}] scanned {scanned >> 20} MiB of writable memory: '
                      f'witness script #1 (1,546 bytes) whole at {len(hits["script0"])} addresses '
                      f'({alone} on its own, {len(inside)} inside a whole-file copy); '
                      f'complete 37,975-byte file at {len(full)} addresses')
        return full

    def run_test(self):
        node = self.nodes[0]
        raw = fetch_tx()
        img = raw[raw.find(SIG):]           # tail -c +1073 of the raw tx: the file itself
        assert len(img) == IMG_LEN
        scripts = mainnet_witness_scripts(raw)
        assert len(scripts) == 25
        self.log.info(f'mainnet witness scripts: {len(scripts)}, sizes {sorted(set(len(s) for s in scripts))}')

        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 120)
        info = node.getblockchaininfo()
        self.log.info(f'node {node.getnetworkinfo()["subversion"]}, height {info["blocks"]}, fork at 100, node args: {node.extra_args}')
        pid = node.process.pid

        sender = node.add_p2p_connection(QuietPeer())    # hands the node the transactions
        fetcher = node.add_p2p_connection(QuietPeer())   # asks the node for them afterwards

        # Funding tx: 25 P2WSH outputs to the mainnet scripts, plus two for the cap check.
        # It carries script hashes only, no image bytes.
        fund = self.wallet.create_self_transfer(fee_rate=0)['tx']
        extra = [dead_branch_script(256), dead_branch_script(257)]
        outs = [p2wsh(s) for s in scripts + extra]
        fund.vout[0].nValue -= 2000 * len(outs) + 5000
        for spk in outs:
            fund.vout.append(CTxOut(2000, spk))
        sender.send_and_ping(msg_tx(fund))
        fund_txid = fund.rehash()
        assert fund_txid in node.getrawmempool()
        self.generate(self.wallet, 1)

        # The spend: 25 inputs, witness = [script] each, one output.  No signatures exist.
        tx = CTransaction()
        tx.version = 2
        for i in range(25):
            tx.vin.append(CTxIn(COutPoint(int(fund_txid, 16), i + 1)))
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[i].scriptWitness.stack = [scripts[i]]
        tx.vout.append(CTxOut(25 * 2000 - 15000, self.wallet._scriptPubKey))
        txid = tx.rehash()
        wtxid = tx.calc_sha256(True)
        wire = tx.serialize_with_witness()
        off = wire.find(SIG)
        assert wire[off:] == img, 'regtest tx tail differs from the mainnet image'
        self.log.info(f'regtest tx {txid}: {len(wire)} bytes on the wire, JXL signature at byte {off}, tail of {len(wire) - off} bytes == the mainnet file')

        # 1. Over P2P, as on mainnet.  Mempool acceptance is checked with getrawmempool,
        #    which returns txids only; nothing has serialized the transaction yet.
        sender.send_and_ping(msg_tx(tx))
        entry = node.getmempoolentry(txid)
        self.log.info(f'accepted to the mempool from a tx message under Knots default policy + RDTS: vsize {entry["vsize"]}')
        full1 = self.report('1 in mempool, no serializing RPC yet', pid, scripts, img)

        # 2. A peer fetches it.  The node announces it first (a few seconds on an inbound peer),
        #    then serves the getdata by serializing the whole transaction into one send buffer.
        fetcher.wait_until(lambda: any(i.hash == wtxid for i in fetcher.last_message['inv'].inv) if 'inv' in fetcher.last_message else False)
        mark = len(fetcher.raw)
        fetcher.send_message(msg_getdata([CInv(MSG_WTX, wtxid)]))
        fetcher.wait_for_tx(txid)
        i = fetcher.raw.find(SIG, mark)
        assert i != -1 and fetcher.raw[i:i + IMG_LEN] == img
        self.log.info(f'peer fetched the tx: the tx message as it came off the socket carries the file whole at payload byte {i - mark - 24}')
        full2 = self.report('2 after a peer fetched the tx', pid, scripts, img)

        # 3. Mined, then a peer fetches the block.  The node answers a block getdata by reading the
        #    raw block from blk*.dat into one buffer and sending it.
        bh = self.generate(self.wallet, 1)[0]
        blk = node.getblock(bh, 1)
        assert txid in blk['tx']
        self.log.info(f'mined in regtest block {blk["height"]} ({bh})')
        mark = len(fetcher.raw)
        fetcher.send_message(msg_getdata([CInv(MSG_BLOCK | MSG_WITNESS_FLAG, int(bh, 16))]))
        fetcher.wait_for_block(int(bh, 16))
        i = fetcher.raw.find(SIG, mark)
        assert i != -1 and fetcher.raw[i:i + IMG_LEN] == img
        self.log.info(f'peer fetched the block: the block message as it came off the socket carries the file whole at payload byte {i - mark - 24}')
        full3 = self.report('3 after a peer fetched the block', pid, scripts, img)

        # The cap the node enforces: 256-byte push passes, 257-byte push fails, same shape.
        # These two transactions carry no image bytes.
        for j, s in enumerate(extra):
            t = CTransaction(); t.version = 2
            t.vin.append(CTxIn(COutPoint(int(fund_txid, 16), 26 + j)))
            t.wit.vtxinwit.append(CTxInWitness()); t.wit.vtxinwit[0].scriptWitness.stack = [s]
            t.vout.append(CTxOut(1500, self.wallet._scriptPubKey))
            r = node.testmempoolaccept([t.serialize().hex()])[0]
            self.log.info(f'dead-branch push of {len(s) - 7} bytes: allowed={r["allowed"]} {r.get("reject-reason", "")}')

        # Render the bytes read out of the node's memory.
        full = full3 or full2 or full1
        assert full, 'image not found contiguous in node memory'
        fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
        data = os.pread(fd, IMG_LEN, full[0])
        os.close(fd)
        out = os.path.join(HERE, 'from_ram.jxl')
        open(out, 'wb').write(data)
        png = os.path.join(HERE, 'from_ram.png')
        r = subprocess.run(['djxl', out, png], capture_output=True, text=True)
        self.log.info(f'djxl on the bytes read from the node\'s memory: {r.stderr.strip().splitlines()[-2:] if r.stderr else r.stdout}')
        assert os.path.exists(png)
        assert data == img
        self.log.info('bytes read from bitcoind RAM == the file cut from the mainnet tx, byte for byte')

if __name__ == '__main__':
    RamDemo(__file__).main()
