#!/usr/bin/env python3
"""A Knots regtest node validates the JXL-n-hide transaction shape under the
BLAKE2b flag day rules (RDTS/BIP110 active) with the Knots default relay
policy on.  Its process memory is then searched for the image.

The 25 witness scripts are the mainnet ones from
23e8f9466cd895c21a041155dba377f1a77a46cec13dcb14c430fa9c75f8786a (block 969961).
The raw transaction is fetched from mempool.guide on first run and cached as tx.bin.

Run from a Bitcoin Knots source tree with a build:
    PYTHONPATH=<knots>/test/functional python3 ram_demo.py --configfile <knots>/build/test/config.ini
Needs djxl from libjxl-tools for the final render.
"""
import hashlib, os, re, struct, subprocess, urllib.request
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness
from test_framework.script import CScript
from test_framework.wallet import MiniWallet

HERE = os.path.dirname(os.path.abspath(__file__))
TXID = '23e8f9466cd895c21a041155dba377f1a77a46cec13dcb14c430fa9c75f8786a'
SIG = bytes.fromhex('0000000c4a584c200d0a870a')  # JPEG XL container signature box

def fetch_tx():
    path = os.path.join(HERE, 'tx.bin')
    if not os.path.exists(path):
        hexdata = urllib.request.urlopen(f'https://mempool.guide/api/tx/{TXID}/hex').read().strip()
        open(path, 'wb').write(bytes.fromhex(hexdata.decode()))
    raw = open(path, 'rb').read()
    return raw

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

class RamDemo(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Fork at 100 with a far expiry: every block after the warmup is under RDTS.
        # -corepolicy=0 restores the Knots default relay policy the framework turns off.
        self.extra_args = [['-testactivationheight=blake2b@100', '-rdtsexpiry=2000000000', '-corepolicy=0']]

    def scan_memory(self, pid, needles):
        """Return {name: [addresses]} of every occurrence of each needle in the
        writable mappings of pid, plus the full bytes at the first hit."""
        hits = {name: [] for name in needles}
        first = {}
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
                            if name not in first:
                                try:
                                    first[name] = os.pread(fd, 37975 if name == 'jxl' else len(needle), addr)
                                except OSError:
                                    pass
                        i = buf.find(needle, i + 1)
                tail = buf[-longest:]
                scanned += len(chunk)
                pos += n
        os.close(fd)
        return hits, first, scanned

    def run_test(self):
        node = self.nodes[0]
        raw = fetch_tx()
        img = raw[raw.find(SIG):]           # tail -c +1073 of the raw tx: the file itself
        assert len(img) == 37975
        scripts = mainnet_witness_scripts(raw)
        assert len(scripts) == 25
        self.log.info(f'mainnet witness scripts: {len(scripts)}, sizes {sorted(set(len(s) for s in scripts))}')

        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 120)
        info = node.getblockchaininfo()
        self.log.info(f'node {node.getnetworkinfo()["subversion"]}, height {info["blocks"]}, fork at 100, node args: {node.extra_args}')

        # Funding tx: 25 P2WSH outputs to the mainnet scripts, plus two for the cap check.
        fund = self.wallet.create_self_transfer(fee_rate=0)['tx']
        extra = [dead_branch_script(256), dead_branch_script(257)]
        outs = [p2wsh(s) for s in scripts + extra]
        fund.vout[0].nValue -= 2000 * len(outs) + 5000
        for spk in outs:
            fund.vout.append(CTxOut(2000, spk))
        fund_txid = self.wallet.sendrawtransaction(from_node=node, tx_hex=fund.serialize().hex())
        self.generate(self.wallet, 1)

        # The spend: 25 inputs, witness = [script] each, one output.  No signatures exist.
        tx = CTransaction()
        tx.version = 2
        for i in range(25):
            tx.vin.append(CTxIn(COutPoint(int(fund_txid, 16), i + 1)))
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[i].scriptWitness.stack = [scripts[i]]
        tx.vout.append(CTxOut(25 * 2000 - 15000, self.wallet._scriptPubKey))
        hex_tx = tx.serialize().hex()
        res = node.testmempoolaccept([hex_tx])[0]
        self.log.info(f'testmempoolaccept under Knots default policy + RDTS: {res}')
        assert res['allowed'], res
        txid = node.sendrawtransaction(hex_tx, 0)
        bh = self.generate(self.wallet, 1)[0]
        blk = node.getblock(bh, 1)
        assert txid in blk['tx']
        self.log.info(f'mined {txid} in regtest block {blk["height"]} ({bh}), tx vsize {res["vsize"]}')

        # The serialized regtest tx carries the same file bytes as mainnet.
        got = bytes.fromhex(node.getrawtransaction(txid, False, bh))
        off = got.find(SIG)
        assert got[off:] == img, 'regtest tx tail differs from the mainnet image'
        self.log.info(f'raw regtest tx: JXL signature at byte {off}, tail of {len(got) - off} bytes == the mainnet file')

        # The cap the node enforces: 256-byte push passes, 257-byte push fails, same shape.
        for j, s in enumerate(extra):
            t = CTransaction(); t.version = 2
            t.vin.append(CTxIn(COutPoint(int(fund_txid, 16), 26 + j)))
            t.wit.vtxinwit.append(CTxInWitness()); t.wit.vtxinwit[0].scriptWitness.stack = [s]
            t.vout.append(CTxOut(1500, self.wallet._scriptPubKey))
            r = node.testmempoolaccept([t.serialize().hex()])[0]
            self.log.info(f'dead-branch push of {len(s) - 7} bytes: allowed={r["allowed"]} {r.get("reject-reason", "")}')

        # Bring the block through the node once more (disk -> CBlock -> serialized reply), then read its memory.
        node.getblock(bh, 0)
        pid = node.process.pid
        needles = {'jxl': SIG, 'script0': scripts[0]}
        hits, first, scanned = self.scan_memory(pid, needles)
        self.log.info(f'scanned {scanned // 1024 // 1024} MiB of writable memory of bitcoind pid {pid}')
        fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        full = [a for a in hits['jxl'] if os.pread(fd, 37975, a) == img]
        self.log.info(f'witness script #1 (1,546 bytes) found whole at {len(hits["script0"])} addresses: {[hex(a) for a in hits["script0"]]}')
        for a in hits['jxl']:
            kind = 'complete 37,975-byte file' if a in full else 'script buffer only (1,546 bytes, unrelated heap after it)'
            self.log.info(f'  JXL signature at {hex(a)}: {kind}')
        self.log.info(f'{len(full)} contiguous copies of the whole image in bitcoind memory')
        assert full, 'image not found contiguous in node memory'
        out = os.path.join(HERE, 'from_ram.jxl')
        open(out, 'wb').write(os.pread(fd, 37975, full[0]))
        os.close(fd)
        png = os.path.join(HERE, 'from_ram.png')
        r = subprocess.run(['djxl', out, png], capture_output=True, text=True)
        self.log.info(f'djxl on the bytes read from /proc/{pid}/mem: {r.stderr.strip().splitlines()[-2:] if r.stderr else r.stdout}')
        assert os.path.exists(png)
        assert open(out, 'rb').read() == img
        self.log.info('bytes read from bitcoind RAM == the file cut from the mainnet tx, byte for byte')

if __name__ == '__main__':
    RamDemo(__file__).main()
