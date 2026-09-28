# Contiguous image in a validating Knots node

On the Knots Discord on 2026-09-28 I was asked to show how any BIP110 compatible format can store more than 256 bytes contiguously in RAM. This is the answer.

The witness script. BIP110 caps pushes and stack items at 256 bytes, not the P2WSH script that holds them. A Knots node validating `23e8f9466cd895c21a041155dba377f1a77a46cec13dcb14c430fa9c75f8786a` (block 969961) under the fork rules holds the whole 37,975-byte JPEG XL file in one contiguous run of RAM. `ram_demo.py` reads it out of a validating node's `/proc/<pid>/mem` and `djxl` renders it.

![the image, read out of bitcoind's memory](from_ram.png)

## What the script does

1. Starts one Knots 29.4.2 regtest node with the BLAKE2b fork, and so RDTS/BIP110, active from height 100, and the Knots default relay policy on (`-corepolicy=0`).
2. Funds the 25 witness scripts of the mainnet transaction and spends them the same way. No signatures exist; each script is `OP_1 OP_NOTIF <data> OP_ENDIF OP_1`.
3. Checks the node enforces the cap on this shape: a 256-byte push is accepted, a 257-byte push is rejected.
4. Reads the node's own memory and searches it for the file.

## Result

```
mainnet witness scripts: 25, sizes [775, 1546]
node /Satoshi:29.4.2(testnode0)/Knots:20260508/, height 120, fork at 100, node args: ['-testactivationheight=blake2b@100', '-rdtsexpiry=2000000000', '-corepolicy=0']
testmempoolaccept under Knots default policy + RDTS: allowed: True, vsize: 10574
mined ecd8e1ab52e3e4121046e4cee62778692c3c77c6506a268e574444098f52988f in regtest block 122
raw regtest tx: JXL signature at byte 1084, tail of 37975 bytes == the mainnet file
dead-branch push of 256 bytes: allowed=True 
dead-branch push of 257 bytes: allowed=False mempool-script-verify-flag-failed (Push value size limit exceeded)
scanned 312 MiB of writable memory of bitcoind
witness script #1 (1,546 bytes) found whole at 5 addresses
  JXL signature at 0x7b489402f49c: complete 37,975-byte file
  JXL signature at 0x7b4898016fbc: complete 37,975-byte file
  JXL signature at 0x7b489802a7c4: script buffer only (1,546 bytes, unrelated heap after it)
  JXL signature at 0x7b48a40112f5: complete 37,975-byte file
  JXL signature at 0x7b48b4022bb5: complete 37,975-byte file
4 contiguous copies of the whole image in bitcoind memory
djxl on the bytes read from /proc/<pid>/mem: Decoded to pixels. 486 x 224
bytes read from bitcoind RAM == the file cut from the mainnet tx, byte for byte
```

The full log is in `ram_demo.log`. Four complete copies of the file and five whole copies of the 1,546-byte witness script were in memory; the counts move a little between runs with heap layout, and every run so far held at least two complete copies. The bytes read out of RAM are byte for byte the tail of the mainnet transaction from offset 1073, and `djxl` renders them to the 486x224 image above, a pie chart of pool hashrate share.

## Why the cap does not reach it

The 256-byte limit is checked on every push the interpreter reads, executed or not (the `max_element_size` check in `EvalScript`, `src/script/interpreter.cpp`), and on every witness stack item after the script has been popped off the stack. The script itself is one byte array, bounded by 3,600 bytes under standard policy and 10,000 under consensus, and RDTS left both alone.

Inside the script the image sits in 255-byte pushes with a 2-byte PUSHDATA1 header between them. The encoder wrapped each header in a JPEG XL `free` box, the padding box the container standard defines, and an 18-byte one across each input boundary. The framing bytes are part of the file, so nothing is reassembled. No stack item over 256 bytes exists anywhere in the transaction; the dead branch never executes, so its pushes never become stack items at all.

## On disk too

`carve.sh` needs no node. It fetches the raw transaction and the raw block from mempool.guide, cuts the file out with `tail -c`, and renders it with `djxl` from both. Block 969961 as every node wrote it to `blk*.dat` carries the file at offset 43022, and `djxl` decodes it from there with the following transactions still attached.

## Run it

Needs a Bitcoin Knots source tree with a build (29.4.2 or later) and `djxl` from libjxl-tools. The log above came from the `29.x-knots` tree at 29.4.2 with Knots PR #435 applied, a rule for 1-of-N multisig inputs that this transaction does not have; the node reports itself as `/Satoshi:29.4.2/Knots:20260508/`. The raw transaction is fetched from mempool.guide on first run.

```
PYTHONPATH=<knots>/test/functional python3 ram_demo.py --configfile <knots>/build/test/config.ini
```

The memory read works because the test framework is bitcoind's parent process, which the default `ptrace_scope=1` allows.
