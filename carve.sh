#!/bin/sh
# Reproduce the contiguity claim with public data only (needs curl, xxd, djxl from libjxl-tools).
set -e
TX=23e8f9466cd895c21a041155dba377f1a77a46cec13dcb14c430fa9c75f8786a
curl -s https://mempool.guide/api/tx/$TX/hex | xxd -p -r > tx.bin
tail -c +1073 tx.bin > img.jxl
jxlinfo img.jxl | head -3
djxl img.jxl out.png
# Same bytes as every node wrote to blk*.dat: carve from the raw block, following txs still attached.
H=$(curl -s https://mempool.guide/api/block-height/969961)
curl -s https://mempool.guide/api/block/$H/raw > block.bin
OFF=$(grep -obUaP '\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a' block.bin | head -1 | cut -d: -f1)
echo "JXL signature at block offset $OFF"
tail -c +$((OFF+1)) block.bin > carve.jxl
djxl carve.jxl carve.png
