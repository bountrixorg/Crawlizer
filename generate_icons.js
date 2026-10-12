const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync } = require('child_process');

// If update_icons.ps1 is available, use high-res crest image resampling with circular alpha mask
const psScript = path.join(__dirname, 'update_icons.ps1');
if (fs.existsSync(psScript) && process.platform === 'win32') {
  try {
    console.log('Generating high-resolution icons from Katana Crest using PowerShell...');
    execSync(`powershell -ExecutionPolicy Bypass -File "${psScript}"`, { stdio: 'inherit' });
    process.exit(0);
  } catch (err) {
    console.warn('PowerShell generation skipped, falling back to procedural generator:', err.message);
  }
}

function createPNG(size) {
  const width = size;
  const height = size;
  const buffer = Buffer.alloc(height * (width * 4 + 1));
  let offset = 0;
  
  for (let y = 0; y < height; y++) {
    buffer[offset++] = 0; // Filter type 0
    for (let x = 0; x < width; x++) {
      const nx = (x / width) * 2 - 1;
      const ny = (y / height) * 2 - 1;
      const dist = Math.sqrt(nx * nx + ny * ny);
      
      if (dist <= 0.95) {
        const blade = Math.abs(nx + ny);
        if (blade < 0.18 && dist < 0.8) {
          buffer[offset++] = 0;   // R
          buffer[offset++] = 230; // G
          buffer[offset++] = 255; // B
          buffer[offset++] = 255; // A
        } else if (blade < 0.28 && dist < 0.8) {
          buffer[offset++] = 255; // R
          buffer[offset++] = 45;  // G
          buffer[offset++] = 145; // B
          buffer[offset++] = 255; // A
        } else {
          const bgShade = Math.floor(18 + (1 - dist) * 25);
          buffer[offset++] = bgShade;
          buffer[offset++] = bgShade + 4;
          buffer[offset++] = bgShade + 14;
          buffer[offset++] = 255;
        }
      } else {
        buffer[offset++] = 0;
        buffer[offset++] = 0;
        buffer[offset++] = 0;
        buffer[offset++] = 0;
      }
    }
  }

  function crc32(buf) {
    let table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
      table[i] = c;
    }
    let crc = -1;
    for (let i = 0; i < buf.length; i++) crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xFF];
    return (crc ^ (-1)) >>> 0;
  }

  function chunk(type, data) {
    const typeBuf = Buffer.from(type, 'ascii');
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(data.length, 0);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const idatData = zlib.deflateSync(buffer);
  const signature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  
  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', idatData),
    chunk('IEND', Buffer.alloc(0))
  ]);
}

if (!fs.existsSync('icons')) {
  fs.mkdirSync('icons');
}

[16, 32, 48, 128].forEach(size => {
  fs.writeFileSync('icons/icon' + size + '.png', createPNG(size));
  console.log('Created icon' + size + '.png');
});
