const MAX_PAGE = BigInt(
  "115792089237316195423570985008687907852837564279074904382605163141518161494337"
);
let currentPage = 1n; 
let isCompressed = true; 

const P = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); 
const Gx = BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"); 
const Gy = BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"); 



function mod(a, m) {
  return ((a % m) + m) % m;
}

function inverseMod(a, m) {
  a = mod(a, m);
  if (a === 0n) throw new Error("Обратного элемента нет");

  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];

  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }

  if (oldR !== 1n) throw new Error("Обратного элемента нет");
  return mod(oldS, m);
}

function pointAdd(xp, yp, xq, yq) {
  // Точка на бесконечности
  if (xp === 0n && yp === 0n) return [xq, yq];
  if (xq === 0n && yq === 0n) return [xp, yp];

  // P + (-P) = точка на бесконечности
  if (xp === xq && mod(yp + yq, P) === 0n) {
    return [0n, 0n];
  }

  let slope;

  if (xp === xq && yp === yq) {
    if (yp === 0n) return [0n, 0n];

    slope = mod(
      3n * xp * xp * inverseMod(2n * yp, P),
      P
    );
  } else {
    slope = mod(
      (yq - yp) * inverseMod(xq - xp, P),
      P
    );
  }

  const xr = mod(slope * slope - xp - xq, P);
  const yr = mod(slope * (xp - xr) - yp, P);

  return [xr, yr];
}

function getPublicKeyBytes(privKeyBigInt, compressed) { 
  let [xr, yr] = [0n, 0n]; 
  let [baseX, baseY] = [Gx, Gy]; 
  let bits = privKeyBigInt; 
  while (bits > 0n) { 
    if (bits % 2n === 1n) [xr, yr] = pointAdd(xr, yr, baseX, baseY); 
    [baseX, baseY] = pointAdd(baseX, baseY, baseX, baseY); 
    bits /= 2n; 
  } 
  let xHex = xr.toString(16).padStart(64, '0'); 
  let pubKeyBytes = []; 
  if (compressed) { 
    let prefix = (yr % 2n === 0n) ? 2 : 3; 
    pubKeyBytes.push(prefix); 
    for (let i = 0; i < xHex.length; i += 2) { 
      pubKeyBytes.push(parseInt(xHex.substr(i, 2), 16)); 
    } 
  } else { 
    let yHex = yr.toString(16).padStart(64, '0'); 
    pubKeyBytes.push(4); 
    for (let i = 0; i < xHex.length; i += 2) { 
      pubKeyBytes.push(parseInt(xHex.substr(i, 2), 16)); 
    } 
    for (let i = 0; i < yHex.length; i += 2) { 
      pubKeyBytes.push(parseInt(yHex.substr(i, 2), 16)); 
    } 
  } 
  return new Uint8Array(pubKeyBytes); 
} 


function sha256Sync(bytes) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  const length = bytes.length;
  const paddedLength = Math.ceil((length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);

  padded.set(bytes);
  padded[length] = 0x80;

  const view = new DataView(padded.buffer);
  const bitLength = length * 8;

  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);

  let h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  for (let offset = 0; offset < paddedLength; offset += 64) {
    const w = new Int32Array(64);

    for (let i = 0; i < 16; i++) {
      w[i] = view.getInt32(offset + i * 4, false);
    }

    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^
                 rotr(w[i - 15], 18) ^
                 (w[i - 15] >>> 3);

      const s1 = rotr(w[i - 2], 17) ^
                 rotr(w[i - 2], 19) ^
                 (w[i - 2] >>> 10);

      w[i] = (
        w[i - 16] + s0 + w[i - 7] + s1
      ) | 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);

      const temp1 = (
        hh + S1 + ch + K[i] + w[i]
      ) | 0;

      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);

      const temp2 = (S0 + maj) | 0;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
    h[5] = (h[5] + f) | 0;
    h[6] = (h[6] + g) | 0;
    h[7] = (h[7] + hh) | 0;
  }

  const result = new Uint8Array(32);
  const out = new DataView(result.buffer);

  for (let i = 0; i < 8; i++) {
    out.setUint32(i * 4, h[i], false);
  }

  return result;
}


// RIPEMD-160 с динамическим расчетом индексов (без ломающихся массивов констант)


function ripemd160(buffer) {
  const R = [
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
  ];

  const RR = [
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
  ];

  const S = [
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
  ];

  const SS = [
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
  ];

  const K = [
    0x00000000, 0x5a827999, 0x6ed9eba1,
    0x8f1bbcdc, 0xa953fd4e
  ];

  const KK = [
    0x50a28be6, 0x5c4dd124, 0x6d703ef3,
    0x7a6d76e9, 0x00000000
  ];

  function f(j, x, y, z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }

  function rol(x, n) {
    return (x << n) | (x >>> (32 - n));
  }

  const len = buffer.length;
  const bitLen = len * 8;
  const paddedLen = Math.ceil((len + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);

  padded.set(buffer);
  padded[len] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 8, bitLen >>> 0, true);
  view.setUint32(
    paddedLen - 4,
    Math.floor(bitLen / 0x100000000),
    true
  );

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  for (let offset = 0; offset < paddedLen; offset += 64) {
    const X = new Int32Array(16);

    for (let i = 0; i < 16; i++) {
      X[i] = view.getInt32(offset + i * 4, true);
    }

    let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    let ar = h0, br = h1, cr = h2, dr = h3, er = h4;

    for (let j = 0; j < 80; j++) {
      const r = Math.floor(j / 16);

      let t = (
        rol(
          (al + f(j, bl, cl, dl) + X[R[j]] + K[r]) | 0,
          S[j]
        ) + el
      ) | 0;

      al = el;
      el = dl;
      dl = rol(cl, 10);
      cl = bl;
      bl = t;

      const rightFunctionIndex = 64 - r * 16 + (j % 16);

      t = (
        rol(
          (
            ar +
            f(rightFunctionIndex, br, cr, dr) +
            X[RR[j]] +
            KK[r]
          ) | 0,
          SS[j]
        ) + er
      ) | 0;

      ar = er;
      er = dr;
      dr = rol(cr, 10);
      cr = br;
      br = t;
    }

    const temp = (h1 + cl + dr) | 0;

    h1 = (h2 + dl + er) | 0;
    h2 = (h3 + el + ar) | 0;
    h3 = (h4 + al + br) | 0;
    h4 = (h0 + bl + cr) | 0;
    h0 = temp;
  }

  const result = new Uint8Array(20);
  const out = new DataView(result.buffer);

  out.setUint32(0, h0, true);
  out.setUint32(4, h1, true);
  out.setUint32(8, h2, true);
  out.setUint32(12, h3, true);
  out.setUint32(16, h4, true);

  return result;
}



function btcHash160(pubKeyBytes) { 
  return ripemd160(sha256Sync(pubKeyBytes)); 
} 

function base58Check(payload) { 
  const versioned = new Uint8Array([0x00, ...payload]); 
  const checksum = sha256Sync(sha256Sync(versioned)).slice(0, 4); 
  const fullData = new Uint8Array(versioned.length + 4); 
  fullData.set(versioned, 0); 
  fullData.set(checksum, versioned.length); 
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; 
  let num = 0n; 
  for (let i = 0; i < fullData.length; i++) num = (num << 8n) + BigInt(fullData[i]); 
  let res = ""; 
  while (num > 0n) { 
    res = alphabet[Number(num % 58n)] + res; 
    num /= 58n; 
  } 
  for (let i = 0; i < fullData.length && fullData[i] === 0; i++) res = alphabet[0] + res; 
  return res; 
} 

function hexToWifCompressed(privKeyHex) {
    const extendedKeyHex = "80" + privKeyHex + "01";
    const bytes = [];
    for (let i = 0; i < extendedKeyHex.length; i += 2) {
        bytes.push(parseInt(extendedKeyHex.substr(i, 2), 16));
    }
    return base58Check(bytes); 
}

function hexToWifCompressed(privKeyHex) {
  const keyBytes = [];
  for (let i = 0; i < privKeyHex.length; i += 2) {
    keyBytes.push(parseInt(privKeyHex.substr(i, 2), 16));
  }
  
  // Создаем payload сразу с префиксом 0x80 и суффиксом 0x01
  const payload = new Uint8Array([0x80, ...keyBytes, 0x01]);
  const checksum = sha256Sync(sha256Sync(payload)).slice(0, 4);
  
  const fullData = new Uint8Array(payload.length + 4);
  fullData.set(payload, 0);
  fullData.set(checksum, payload.length);
  
  // Чистый перевод в Base58 без добавления лишних байт
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (let i = 0; i < fullData.length; i++) num = (num << 8n) + BigInt(fullData[i]);
  
  let res = "";
  while (num > 0n) {
    res = alphabet[Number(num % 58n)] + res;
    num /= 58n;
  }
  for (let i = 0; i < fullData.length && fullData[i] === 0; i++) res = alphabet[0] + res;
  return res;
}


function generateBitcoinAddress(privKeyHex, compressed) { 
  const privBigInt = BigInt("0x" + privKeyHex); 
  if (privBigInt === 0n) return "Невалидный ключ"; 
  let pubKeyBytes = getPublicKeyBytes(privBigInt, compressed); 
  return base58Check(btcHash160(pubKeyBytes)); 
} 

function parsePageValue(value) { 
  try { 
    let clean = value.toString().replace(/[^0-9]/g, ''); 
    if (!clean) return 1n; 
    let val = BigInt(clean); 
    return val < 1n ? 1n : (val > MAX_PAGE ? MAX_PAGE : val); 
  } catch(e) { 
    return 1n; 
  } 
} 

function renderPage() { 
  const pageInput = document.getElementById('page-input'); 
  if (pageInput) pageInput.value = currentPage.toString(); 
  const tbody = document.getElementById('keys-table-body'); 
  if (!tbody) return; 
  tbody.innerHTML = ''; 
  
  for (let i = 0n; i < 10n; i++) { 
    const calculatedIndex = (currentPage - 1n) * 10n + i + 1n; 
    const privKeyHex = calculatedIndex.toString(16).padStart(64, '0'); 
    let realAddress = "";
    
    try {
      realAddress = generateBitcoinAddress(privKeyHex, isCompressed); 
    } catch (err) {
      realAddress = "Ошибка расчета (" + err.message + ")";
    }
    
// 1. Генерация данных
const wifCompressed = hexToWifCompressed(privKeyHex);
const compAddr = generateBitcoinAddress(privKeyHex, true);
const uncompAddr = generateBitcoinAddress(privKeyHex, false);

// 2. Отрисовка строки таблицы в новом порядке
const row = document.createElement('tr'); 
row.innerHTML = `<td>${Number(i) + 1}</td>` +
  `<td class="hex-key">${privKeyHex}</td>` +
  `<td><strong>${compAddr}</strong></td>` + // 1-й адрес
  `<td><strong>${uncompAddr}</strong></td>` + // 2-й адрес
  `<td><span style="color: #e67e22; font-family: monospace;">${wifCompressed}</span></td>`; // WIF в конце
tbody.appendChild(row);


 
  } 
} 

function changePage(direction) { 
  currentPage += BigInt(direction); 
  if (currentPage < 1n) currentPage = 1n; 
  if (currentPage > MAX_PAGE) currentPage = MAX_PAGE; 
  renderPage(); 
} 

function goRandomPage() { 
  const randString = Array.from({length: 64}, () => 
    Math.floor(Math.random() * 16).toString(16) 
  ).join(''); 
  currentPage = (BigInt('0x' + randString) % MAX_PAGE) + 1n; 
  renderPage(); 
} 

window.addEventListener('DOMContentLoaded', () => { 
  const pageInput = document.getElementById('page-input'); 
  const compSelect = document.getElementById('compressed-select'); 
  if (pageInput) { 
    pageInput.addEventListener('input', (e) => { 
currentPage = parsePageValue(e.target.value);
renderPage();
});
}
if (compSelect) {
compSelect.addEventListener('change', (e) => {
isCompressed = (e.target.value === "C");
renderPage();
});
}
renderPage();
});