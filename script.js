// script.js - safe patch (2026-01-07)
// Perubahan utama:
// - Menghapus backdoor admin dan auto-creation akun admin.
// - Menjaga kompatibilitas legacy password (btoa) dan migrasi ke SHA-256 (base64) saat login/register.
// - Mengurangi penggunaan innerHTML di area sensitif untuk mencegah XSS (produk, detail, admin users, cart, orders).
// - Validasi harga/stok diperbaiki (mengizinkan harga = 0, menolak negatif/NaN).
// - Penanganan Cloudinary: cek konfigurasi sebelum upload dan pesan instruktif jika belum diset.
// - Penambahan fitur pembayaran (client-side / simulasi): metode pembayaran, instruksi, paymentRef, status pembayaran, konfirmasi pembayaran.
// - Penambahan fitur upload bukti pembayaran (upload ke Cloudinary jika tersedia, fallback dataURL) + admin approve/reject.

// ---------------- initial data ----------------
const initialProducts = [
    { id:1, name:"Tabung Gas 12kg", price:230000, stock:5, image:"https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQwpflIgpcCt9uD1vQwpcXlwmsB7H9FI9Bjeg&s", description:"Tabung gas 12kg, cocok untuk kebutuhan rumah tangga besar dan usaha kecil." },
    { id:2, name:"Tabung Gas 5kg",  price:120000, stock:10, image:"https://down-id.img.susercontent.com/file/2631ae627a23030df44d74464dedba0a", description:"Tabung gas 5kg, praktis untuk rumah tangga kecil atau portable." },
    { id:3, name:"Tabung Gas 3kg",  price:80000,  stock:15, image:"https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcR2qUf0OG8Lp4hkEg9v9zkQ6xhxWDEnhQA9Vg&s", description:"Tabung gas 3kg, ringan dan mudah dibawa." }
];

// ---------------- Cloudinary configuration (fill these) ----------------
// Ganti nilai di bawah dengan nilai dari dashboard Cloudinary Anda.
// Untuk upload unsigned (tidak direkomendasikan untuk produksi) gunakan preset unsigned.
// Untuk produksi, gunakan signed upload lewat server.
const CLOUDINARY_CLOUD_NAME = "drqzdt0r9";
const CLOUDINARY_UPLOAD_PRESET = "unsigned_products";

// Upload helper untuk Cloudinary (unsigned)
async function uploadToCloudinary(file) {
  if (!file) return null;
  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_UPLOAD_PRESET) {
    throw new Error('Cloudinary belum dikonfigurasi. Set CLOUDINARY_CLOUD_NAME dan CLOUDINARY_UPLOAD_PRESET di script.js untuk mengaktifkan upload gambar dari browser.');
  }
  const url = `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/upload`;
  const fd = new FormData();
  fd.append('file', file);
  fd.append('upload_preset', CLOUDINARY_UPLOAD_PRESET);
  const res = await fetch(url, { method: 'POST', body: fd });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error('Upload Cloudinary gagal: ' + txt);
  }
  const data = await res.json();
  return data.secure_url;
}

// Fallback: baca file jadi dataURL (untuk demo jika Cloudinary tidak dikonfigurasi)
function fileToDataURL(file){
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(fr.result);
    fr.onerror = (e) => reject(e);
    fr.readAsDataURL(file);
  });
}

// ---------------- storage helpers ----------------
function getProductsFromStorage(){
  try { return JSON.parse(localStorage.getItem('products') || 'null') || null; } catch(e){ return null; }
}
function saveProductsToStorage(arr){ localStorage.setItem('products', JSON.stringify(arr)); }
function seedProductsIfNeeded(){ if (!getProductsFromStorage()){ saveProductsToStorage(initialProducts); } }

// ---- users storage and migration (NO auto admin/backdoor) ----
// Support previous isAdmin boolean shape and migrate to { password, role }
function getUsers(){
  const raw = localStorage.getItem('users');
  if (!raw) {
    const empty = {};
    localStorage.setItem('users', JSON.stringify(empty));
    return empty;
  }
  try {
    const parsed = JSON.parse(raw);
    const out = {};
    Object.entries(parsed).forEach(([k,v])=>{
      if (typeof v === 'string') {
        out[k] = { password: v, role: (k === 'admin' ? 'admin' : 'user') };
      } else if (v && typeof v === 'object') {
        if (v.password && v.role) out[k] = { password: v.password, role: v.role };
        else if (v.password && v.isAdmin !== undefined) out[k] = { password: v.password, role: v.isAdmin ? 'admin' : 'user' };
        else if (v.password) out[k] = { password: v.password, role: 'user' };
        else out[k] = { password: btoa(String(v)), role: 'user' };
      } else {
        out[k] = { password: btoa(String(v)), role: 'user' };
      }
    });
    localStorage.setItem('users', JSON.stringify(out));
    return out;
  } catch(e) {
    const empty = {};
    localStorage.setItem('users', JSON.stringify(empty));
    return empty;
  }
}
function saveUsers(u){ localStorage.setItem('users', JSON.stringify(u)); }

// Legacy (insecure) hashing kept for backward compatibility (btoa)
function hash(pw){ try { return btoa(pw); } catch(e){ return pw; } } // demo only

// New: async SHA-256 hash -> base64 (Web Crypto)
function base64ArrayBuffer(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}
async function asyncHash(pw){
  try {
    const enc = new TextEncoder();
    const data = enc.encode(pw);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return base64ArrayBuffer(hashBuffer);
  } catch(e){
    // fallback ke legacy btoa if Web Crypto tidak tersedia
    return hash(pw);
  }
}

let currentUser = localStorage.getItem('currentUser') || null;
let cart = [];

// cart load/save per user
function loadCartForUser(){ cart = []; if (!currentUser) return; try { cart = JSON.parse(localStorage.getItem(`cart_${currentUser}`) || '[]'); } catch(e){ cart = []; } }
function saveCartForUser(){ if (!currentUser) return; localStorage.setItem(`cart_${currentUser}`, JSON.stringify(cart)); }

// orders per user
function getOrdersForUser(){ if (!currentUser) return []; try { return JSON.parse(localStorage.getItem(`orders_${currentUser}`) || '[]'); } catch(e){ return []; } }
function saveOrdersForUser(arr){ if (!currentUser) return; localStorage.setItem(`orders_${currentUser}`, JSON.stringify(arr)); }
function saveOrderForUser(order){ if (!currentUser) return; const arr = getOrdersForUser(); arr.unshift(order); localStorage.setItem(`orders_${currentUser}`, JSON.stringify(arr)); }

// utils
function escapeHtml(s){ if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function showToast(msg, type='info'){ const t = document.getElementById('toast'); if(!t) return; t.textContent = msg; t.classList.add('show'); setTimeout(()=> t.classList.remove('show'), 3000); }

// ---------------- product management ----------------
function getProducts(){ const p = getProductsFromStorage(); return p ? p : []; }
function findProduct(id){ return getProducts().find(x=>x.id===Number(id)); }
function getAvailableStock(id){ const prod = findProduct(id); return prod ? Number(prod.stock||0) : 0; }
function updateProductStock(id, newStock){ const prods = getProducts(); const idx = prods.findIndex(p=>p.id===Number(id)); if (idx === -1) return false; prods[idx].stock = Number(newStock); saveProductsToStorage(prods); return true; }
function addProduct(product){ const prods = getProducts(); product.id = prods.length ? (Math.max(...prods.map(p=>p.id))+1) : 1; prods.push(product); saveProductsToStorage(prods); return product.id; }
function updateProduct(product){ const prods = getProducts(); const idx = prods.findIndex(p=>p.id===Number(product.id)); if (idx === -1) return false; prods[idx] = product; saveProductsToStorage(prods); return true; }
function deleteProduct(id){ let prods = getProducts(); prods = prods.filter(p=>p.id!==Number(id)); saveProductsToStorage(prods); return true; }

// ---------------- roles & permission helpers ----------------
function getUserRole(username){
  const users = getUsers();
  if (!users[username]) return null;
  return users[username].role || 'user';
}
function isAdminUser(){ if (!currentUser) return false; const users = getUsers(); return (users[currentUser] && users[currentUser].role === 'admin'); }
function isManagerOrAdmin(){ if (!currentUser) return false; const users = getUsers(); const r = (users[currentUser] && users[currentUser].role) || 'user'; return r === 'admin' || r === 'manager'; }
function requireAdminAction(){ if (!isAdminUser()){ showToast('Akses ditolak: hanya admin', 'error'); return false; } return true; }
function requireManagerOrAdmin(){ if (!isManagerOrAdmin()){ showToast('Akses ditolak: hanya admin/manager', 'error'); return false; } return true; }

// ---------------- header & auth UI ----------------
function updateHeaderUI(){
  const userInfo = document.getElementById('user-info');
  const loginBtn = document.getElementById('login-btn');
  const registerLink = document.getElementById('register-link');
  if (userInfo) userInfo.textContent = currentUser ? `👤 ${currentUser} (${getUserRole(currentUser)})` : '';
  if (loginBtn){
    if (currentUser){
      loginBtn.textContent = 'Logout';
      loginBtn.onclick = () => { logout(); };
      if (registerLink) registerLink.style.display = 'none';
    } else {
      loginBtn.textContent = 'Login';
      loginBtn.onclick = () => { window.location.href = 'login.html'; };
      if (registerLink) registerLink.style.display = 'inline-block';
    }
  }
  const cnt = document.getElementById('cart-count'); if (cnt) cnt.textContent = cart.reduce((s,i)=>s+(i.qty||0),0);
}

// ---------------- render product list (index) ----------------
function makeProductCard(p){
  // safer DOM-building (hindari innerHTML)
  const available = getAvailableStock(p.id);
  const stockText = available > 0 ? `Stok: ${available}` : 'Kosong';
  const disabled = available <= 0;

  const div = document.createElement('div');
  div.className = 'product-card';

  const aImg = document.createElement('a');
  aImg.className = 'view-link';
  aImg.href = `product.html?id=${p.id}`;
  aImg.title = p.name;

  const img = document.createElement('img');
  img.src = p.image;
  img.alt = p.name;
  aImg.appendChild(img);
  div.appendChild(aImg);

  const h3 = document.createElement('h3');
  const aTitle = document.createElement('a');
  aTitle.className = 'view-link';
  aTitle.href = `product.html?id=${p.id}`;
  aTitle.textContent = p.name;
  h3.appendChild(aTitle);
  div.appendChild(h3);

  const priceP = document.createElement('p');
  priceP.textContent = `Rp${Number(p.price).toLocaleString()}`;
  div.appendChild(priceP);

  const stockP = document.createElement('p');
  stockP.style.margin = '6px 0 0';
  stockP.style.color = available > 0 ? '#276870' : '#c0392b';
  stockP.style.fontWeight = '600';
  stockP.textContent = stockText;
  div.appendChild(stockP);

  const actions = document.createElement('div');
  actions.className = 'product-actions';

  const viewLink = document.createElement('a');
  viewLink.className = 'view-link';
  viewLink.href = `product.html?id=${p.id}`;
  viewLink.textContent = 'Lihat';
  actions.appendChild(viewLink);

  const btn = document.createElement('button');
  btn.textContent = 'Tambah ke Keranjang';
  if (disabled) {
    btn.disabled = true;
  } else {
    btn.addEventListener('click', ()=> handleAddToCart(p.id));
  }
  actions.appendChild(btn);

  div.appendChild(actions);

  return div;
}
function renderProducts(){
  const container = document.getElementById('product-container');
  if (!container) return;
  const prods = getProducts();
  const q = (document.getElementById('search-input') && document.getElementById('search-input').value || '').toLowerCase().trim();
  const stockFilter = document.getElementById('filter-stock') ? document.getElementById('filter-stock').value : 'all';
  container.innerHTML = '';
  prods.filter(p=>{
    if (q && !p.name.toLowerCase().includes(q) && !(p.description||'').toLowerCase().includes(q)) return false;
    if (stockFilter === 'in' && getAvailableStock(p.id) <= 0) return false;
    if (stockFilter === 'out' && getAvailableStock(p.id) > 0) return false;
    return true;
  }).forEach(p => container.appendChild(makeProductCard(p)));
}

// ---------------- product detail page ----------------
function renderProductDetail(){
  const el = document.getElementById('product-detail'); if (!el) return;
  const params = new URLSearchParams(location.search); const id = parseInt(params.get('id'),10);
  const product = findProduct(id); if (!product){ el.innerHTML = `<div class="product-detail"><div style="padding:20px">Produk tidak ditemukan. <a href="index.html">Kembali</a></div></div>`; return; }
  const available = getAvailableStock(product.id);

  // Build DOM instead of innerHTML
  el.innerHTML = '';
  const wrapper = document.createElement('div');
  wrapper.className = 'product-detail';

  const left = document.createElement('div');
  left.className = 'left';
  const img = document.createElement('img');
  img.src = product.image;
  img.alt = product.name;
  left.appendChild(img);

  const right = document.createElement('div');
  right.className = 'right';

  const h2 = document.createElement('h2');
  h2.textContent = product.name;
  right.appendChild(h2);

  const priceDiv = document.createElement('div');
  priceDiv.className = 'price';
  priceDiv.textContent = `Rp${product.price.toLocaleString()}`;
  right.appendChild(priceDiv);

  const descDiv = document.createElement('div');
  descDiv.className = 'desc';
  descDiv.textContent = product.description;
  right.appendChild(descDiv);

  const stockDiv = document.createElement('div');
  stockDiv.style.marginBottom = '12px';
  stockDiv.style.color = available>0 ? '#276870' : '#c0392b';
  stockDiv.style.fontWeight = '700';
  stockDiv.textContent = `Stok: ${available>0?available:'Kosong'}`;
  right.appendChild(stockDiv);

  const qtyRow = document.createElement('div');
  qtyRow.className = 'qty-row';
  const lbl = document.createElement('label');
  lbl.textContent = 'Jumlah:';
  qtyRow.appendChild(lbl);
  const minusBtn = document.createElement('button');
  minusBtn.className = 'qty-btn';
  minusBtn.textContent = '-';
  minusBtn.addEventListener('click', ()=> changeQty(-1));
  qtyRow.appendChild(minusBtn);
  const qtyInput = document.createElement('input');
  qtyInput.id = 'detail-qty';
  qtyInput.type = 'number';
  qtyInput.value = 1;
  qtyInput.min = 1;
  qtyRow.appendChild(qtyInput);
  const plusBtn = document.createElement('button');
  plusBtn.className = 'qty-btn';
  plusBtn.textContent = '+';
  plusBtn.addEventListener('click', ()=> changeQty(1));
  qtyRow.appendChild(plusBtn);
  right.appendChild(qtyRow);

  const actions = document.createElement('div');
  const addCartBtn = document.createElement('button');
  addCartBtn.className = 'add-cart-btn';
  addCartBtn.textContent = 'Tambah ke Keranjang';
  if (available <= 0) addCartBtn.disabled = true;
  addCartBtn.addEventListener('click', ()=> addFromDetail(product.id));
  actions.appendChild(addCartBtn);

  const contLink = document.createElement('a');
  contLink.href = 'index.html';
  contLink.style.marginLeft = '12px';
  contLink.style.color = '#127174';
  contLink.textContent = 'Lanjut Belanja';
  actions.appendChild(contLink);

  right.appendChild(actions);

  wrapper.appendChild(left);
  wrapper.appendChild(right);
  el.appendChild(wrapper);
}
function changeQty(delta){ const q = document.getElementById('detail-qty'); if (!q) return; let v = parseInt(q.value,10) || 1; v += delta; if (v<1) v=1; q.value = v; }
function addFromDetail(productId){
  const q = document.getElementById('detail-qty'); const qty = q ? (parseInt(q.value,10)||1) : 1;
  const available = getAvailableStock(productId); const inCart = (cart.find(i=>i.id===productId) || {}).qty || 0;
  if (qty + inCart > available){ showToast(`Stok tidak mencukupi. Tersedia: ${available - inCart}`, 'error'); return; }
  if (!currentUser){ localStorage.setItem('redirectAfterLogin', `add:${productId}:${qty}`); window.location.href='login.html'; return; }
  const prod = findProduct(productId); if (!prod) return;
  const found = cart.find(c=>c.id===productId); if (found) found.qty += qty; else cart.push({...prod, qty});
  saveCartForUser(); updateCartUI(); showToast(`${prod.name} x${qty} ditambahkan ke keranjang`);
}

// ---------------- cart actions ----------------
function handleAddToCart(productId){
  const available = getAvailableStock(productId); const inCart = (cart.find(i=>i.id===productId) || {}).qty || 0;
  if (inCart + 1 > available){ showToast('Stok tidak mencukupi', 'error'); return; }
  if (!currentUser){ localStorage.setItem('redirectAfterLogin', `add:${productId}:1`); window.location.href='login.html'; return; }
  addToCart(productId);
}
function addToCart(productId){ const prod = findProduct(productId); if (!prod) return; const found = cart.find(c=>c.id===productId); if (found) found.qty += 1; else cart.push({...prod, qty:1}); saveCartForUser(); updateCartUI(); showToast(`${prod.name} ditambahkan ke keranjang`); }
function decreaseCartQty(productId){ const item = cart.find(i=>i.id===productId); if (!item) return; if (item.qty > 1) item.qty--; else cart = cart.filter(i=>i.id!==productId); saveCartForUser(); updateCartUI(); }
function increaseCartQty(productId){ const available = getAvailableStock(productId); const item = cart.find(i=>i.id===productId); if (!item) return; if (item.qty + 1 > available){ showToast('Stok tidak mencukupi', 'error'); return; } item.qty++; saveCartForUser(); updateCartUI(); }
function removeFromCart(productId){ cart = cart.filter(i=>i.id!==productId); saveCartForUser(); updateCartUI(); }
function emptyCart(){ cart = []; saveCartForUser(); updateCartUI(); showToast('Keranjang dikosongkan'); }
function updateCartUI(){ const countEl = document.getElementById('cart-count'), list = document.getElementById('cart-items'), totalEl = document.getElementById('cart-total'); if (!countEl || !list || !totalEl) return; const totalQty = cart.reduce((s,i)=>s+(i.qty||0),0); countEl.textContent = totalQty; list.innerHTML = ''; let total = 0; cart.forEach(item=>{ total += item.price * (item.qty||0); const li = document.createElement('li'); // safer composition
  const nameSpan = document.createElement('span');
  nameSpan.textContent = `${item.name} x ${item.qty}`;
  li.appendChild(nameSpan);

  const controls = document.createElement('span');
  controls.style.marginLeft = '8px';

  const decBtn = document.createElement('button');
  decBtn.textContent = '-';
  decBtn.addEventListener('click', ()=> decreaseCartQty(item.id));
  controls.appendChild(decBtn);

  const incBtn = document.createElement('button');
  incBtn.textContent = '+';
  incBtn.addEventListener('click', ()=> increaseCartQty(item.id));
  controls.appendChild(incBtn);

  const remBtn = document.createElement('button');
  remBtn.textContent = 'Hapus';
  remBtn.style.marginLeft = '8px';
  remBtn.addEventListener('click', ()=> removeFromCart(item.id));
  controls.appendChild(remBtn);

  li.appendChild(controls);
  list.appendChild(li);
  }); totalEl.textContent = 'Rp' + total.toLocaleString(); saveCartForUser(); }

// ---------------- checkout & orders (dengan pembayaran sederhana) ----------------
function proceedToCheckout(){ if (!currentUser){ localStorage.setItem('redirectAfterLogin','showCart'); window.location.href='login.html'; return; } if (!cart.length){ showToast('Keranjang kosong', 'error'); return; } window.location.href = 'checkout.html'; }
function renderCheckoutItems(){ const el = document.getElementById('checkout-items'); if (!el) return; if (!currentUser){ window.location.href='login.html'; return; } el.innerHTML = ''; let subtotal = 0; cart.forEach(i=>{ subtotal += i.price * i.qty; const row = document.createElement('div'); row.textContent = `${i.name} x ${i.qty} — Rp${(i.price*i.qty).toLocaleString()}`; el.appendChild(row); }); const sub = document.createElement('div'); sub.style.marginTop = '8px'; sub.style.fontWeight = '700'; sub.id = 'checkout-subtotal'; sub.textContent = `Subtotal: Rp${subtotal.toLocaleString()}`; el.appendChild(sub);

  // Show shipping & total preview (will be recalculated on payment selection/change)
  const shipDiv = document.createElement('div'); shipDiv.id='checkout-shipping'; shipDiv.style.marginTop='6px'; el.appendChild(shipDiv);
  const totDiv = document.createElement('div'); totDiv.id='checkout-total'; totDiv.style.marginTop='6px'; totDiv.style.fontWeight='800'; el.appendChild(totDiv);

  // update totals based on shipping & payment selection
  function updateTotals(){
    const ship = document.getElementById('shipping-method') ? document.getElementById('shipping-method').value : 'reg';
    const shipCost = ship === 'yes' ? 15000 : 0;
    const total = subtotal + shipCost;
    const shipEl = document.getElementById('checkout-shipping');
    if (shipEl) shipEl.textContent = `Ongkir: Rp${shipCost.toLocaleString()}`;
    const totEl = document.getElementById('checkout-total');
    if (totEl) totEl.textContent = `Total: Rp${total.toLocaleString()}`;
    // also update payment instruction preview
    const pm = document.getElementById('payment-method') ? document.getElementById('payment-method').value : 'bank';
    showPaymentPreview(pm, total);
  }

  const shipSel = document.getElementById('shipping-method'); if (shipSel) shipSel.addEventListener('change', updateTotals);
  const paySel = document.getElementById('payment-method'); if (paySel) paySel.addEventListener('change', ()=> { updateTotals(); });

  updateTotals();
}
function placeOrder(){ if (!currentUser){ window.location.href='login.html'; return; } if (!cart.length){ showToast('Keranjang kosong', 'error'); return; } const name = document.getElementById('addr-name').value.trim(); const phone = document.getElementById('addr-phone').value.trim(); const addr = document.getElementById('addr-address').value.trim(); const ship = document.getElementById('shipping-method').value; const payMethod = document.getElementById('payment-method') ? document.getElementById('payment-method').value : 'bank'; if (!name || !phone || !addr){ showToast('Lengkapi alamat pengiriman', 'error'); return; } for (const it of cart){ const available = getAvailableStock(it.id); if (it.qty > available){ showToast(`Stok tidak cukup untuk ${it.name}. Tersedia ${available}`, 'error'); return; } } let subtotal = cart.reduce((s,i)=>s+(i.price*i.qty),0); const shipCost = ship === 'yes' ? 15000 : 0; const total = subtotal + shipCost; const now = new Date().toISOString();

  // prepare payment information (simulasi)
  const payment = preparePaymentForOrder(payMethod, total);

  const order = { id: 'ORD' + Date.now(), date: now, items: cart.map(i=>({id:i.id,name:i.name,price:i.price,qty:i.qty})), subtotal, shipMethod:ship, shipCost, total, address:{name,phone,addr}, paymentMethod: payMethod, paymentStatus: payment.status, paymentRef: payment.ref || '', paymentInstructions: payment.instructions || '', paymentProof: '', paymentProofStatus: '', paymentProofNote: '' };

  // reduce stock
  const prods = getProducts(); order.items.forEach(it=>{ const idx = prods.findIndex(p=>p.id===it.id); if (idx !== -1) prods[idx].stock = Math.max(0, (prods[idx].stock||0) - it.qty); }); saveProductsToStorage(prods);

  // save order (per user)
  saveOrderForUser(order);

  // clear cart
  cart = []; saveCartForUser();

  // Show instruction or navigate
  if (order.paymentStatus === 'pending'){
    showToast('Pesanan dibuat. Periksa instruksi pembayaran di Riwayat Pesanan.', 'success');
  } else if (order.paymentStatus === 'cod_pending'){
    showToast('Pesanan dibuat (COD). Bayar saat pesanan diterima.', 'success');
  } else if (order.paymentStatus === 'paid'){
    showToast('Pesanan dibuat dan terbayar. Terima kasih!', 'success');
  } else {
    showToast('Pesanan dibuat', 'success');
  }

  setTimeout(()=> window.location.href = 'orders.html', 800);
}

// ---------------- payment helpers (simulasi) ----------------
function rand(n){ return Math.floor(Math.random()*n); }
function genPaymentRef(prefix='VA'){ return prefix + (Math.floor(Date.now()/1000) % 100000) + String(Math.floor(Math.random()*90000)+10000); }

// prepare payment for order (client-side simulation)
// returns { status: 'pending'|'paid'|'cod_pending', ref, instructions }
function preparePaymentForOrder(method, total){
  if (method === 'cod'){
    return { status: 'cod_pending', ref: '', instructions: 'Bayar saat pesanan diterima (COD).' };
  }
  if (method === 'bank' || method === 'virtual'){
    const ref = genPaymentRef('VA');
    const instr = `Silakan transfer Rp${total.toLocaleString()} ke nomor Virtual Account: ${ref}. Setelah transfer, unggah bukti pembayaran atau klik "Konfirmasi Pembayaran" pada halaman Riwayat Pesanan. (Ini simulasi.)`;
    return { status: 'pending', ref, instructions: instr };
  }
  if (method === 'qris'){
    const ref = genPaymentRef('QR');
    const instr = `Silakan scan QRIS (kode referensi ${ref}) dan bayar sebesar Rp${total.toLocaleString()}. Setelah bayar, unggah bukti pembayaran atau klik "Konfirmasi Pembayaran" pada halaman Riwayat Pesanan. (Ini simulasi.)`;
    return { status: 'pending', ref, instructions: instr };
  }
  // default
  return { status: 'pending', ref: '', instructions: 'Ikuti instruksi pembayaran.' };
}

// show payment preview on checkout page (informasional)
function showPaymentPreview(method, total){
  const el = document.getElementById('payment-instructions');
  if (!el) return;
  if (method === 'cod'){
    el.textContent = 'Bayar dengan cash saat pesanan diterima (COD). Tidak perlu bayar sekarang.';
    return;
  }
  if (method === 'bank' || method === 'virtual'){
    const ref = genPaymentRef('VA'); // preview ref (not stored until order dibuat)
    el.textContent = `Contoh instruksi: transfer Rp${total.toLocaleString()} ke Virtual Account ${ref}. (Ref contoh, akan digenerate saat pesanan dibuat.)`;
    return;
  }
  if (method === 'qris'){
    const ref = genPaymentRef('QR');
    el.textContent = `Contoh instruksi QRIS: scan kode, bayar Rp${total.toLocaleString()}. Kode ref contoh: ${ref}.`;
    return;
  }
  el.textContent = '';
}

// ---------------- orders page (dengan upload bukti pembayaran) ----------------
function renderOrdersPage(){ if (!currentUser){ window.location.href='login.html'; return; } const wrap = document.getElementById('orders-list'); if (!wrap) return; const orders = getOrdersForUser(); if (!orders.length) { wrap.innerHTML = '<div>Tidak ada pesanan.</div>'; return; } wrap.innerHTML = ''; orders.forEach(o=>{ const div = document.createElement('div'); div.className = 'order-item'; const head = document.createElement('div'); head.style.display='flex'; head.style.justifyContent='space-between'; const strong = document.createElement('strong'); strong.textContent = o.id; const spanDate = document.createElement('span'); spanDate.textContent = new Date(o.date).toLocaleString(); head.appendChild(strong); head.appendChild(spanDate); div.appendChild(head); const itemsTitle = document.createElement('div'); itemsTitle.textContent = 'Items:'; div.appendChild(itemsTitle); const ul = document.createElement('ul'); o.items.forEach(it=>{ const li = document.createElement('li'); li.textContent = `${it.name} x ${it.qty} — Rp${(it.price*it.qty).toLocaleString()}`; ul.appendChild(li); }); div.appendChild(ul); const tot = document.createElement('div'); tot.textContent = `Total: Rp${o.total.toLocaleString()}`; div.appendChild(tot);

  // payment info
  const payDiv = document.createElement('div');
  payDiv.style.marginTop = '8px';
  const pm = document.createElement('div');
  pm.textContent = `Metode Pembayaran: ${o.paymentMethod || 'N/A'}`;
  payDiv.appendChild(pm);
  const pst = document.createElement('div');
  let pstText = o.paymentStatus || 'unknown';
  if (pstText === 'pending') pstText = 'Menunggu pembayaran';
  if (pstText === 'pending_confirmation') pstText = 'Menunggu konfirmasi bukti pembayaran';
  if (pstText === 'cod_pending') pstText = 'Bayar saat diterima (COD)';
  if (pstText === 'paid') pstText = 'Terbayar';
  payDiv.appendChild(Object.assign(document.createElement('div'), { textContent: `Status Pembayaran: ${pstText}` }));

  if (o.paymentRef) {
    const pref = document.createElement('div');
    pref.textContent = `Referensi: ${o.paymentRef}`;
    pref.style.fontSize = '0.95em';
    pref.style.color = '#333';
    payDiv.appendChild(pref);
  }
  if (o.paymentInstructions){
    const pinstr = document.createElement('div');
    pinstr.textContent = o.paymentInstructions;
    pinstr.style.fontSize = '0.95em';
    pinstr.style.color = '#554';
    pinstr.style.marginTop = '6px';
    payDiv.appendChild(pinstr);
  }
  div.appendChild(payDiv);

  // payment proof area
  const proofDiv = document.createElement('div');
  proofDiv.style.marginTop = '10px';
  if (o.paymentProof){
    const imgWrap = document.createElement('div');
    imgWrap.style.display = 'flex';
    imgWrap.style.gap = '8px';
    imgWrap.style.alignItems = 'center';
    const thumb = document.createElement('img');
    thumb.src = o.paymentProof;
    thumb.alt = 'Bukti pembayaran';
    thumb.style.maxWidth = '140px';
    thumb.style.maxHeight = '90px';
    thumb.style.objectFit = 'cover';
    thumb.style.borderRadius = '6px';
    thumb.style.border = '1px solid #eef4f4';
    imgWrap.appendChild(thumb);
    const info = document.createElement('div');
    info.style.fontSize = '0.95em';
    info.style.color = '#333';
    info.textContent = `Status bukti: ${o.paymentProofStatus || 'uploaded'}`;
    imgWrap.appendChild(info);
    proofDiv.appendChild(imgWrap);
    // view full
    const viewBtn = document.createElement('button');
    viewBtn.textContent = 'Lihat Bukti';
    viewBtn.style.marginTop = '8px';
    viewBtn.addEventListener('click', ()=> window.open(o.paymentProof, '_blank'));
    proofDiv.appendChild(viewBtn);
  } else {
    // show upload control only if order is pending payment or pending_confirmation
    if (o.paymentStatus === 'pending' || o.paymentStatus === 'pending_confirmation'){
      const fileInput = document.createElement('input');
      fileInput.type = 'file';
      fileInput.accept = 'image/*';
      fileInput.id = `proof-file-${o.id}`;
      fileInput.style.display = 'inline-block';
      proofDiv.appendChild(fileInput);
      const upBtn = document.createElement('button');
      upBtn.textContent = 'Upload Bukti';
      upBtn.style.marginLeft = '8px';
      upBtn.addEventListener('click', ()=> uploadPaymentProof(o.id));
      proofDiv.appendChild(upBtn);
      const note = document.createElement('div');
      note.style.fontSize = '0.9em';
      note.style.color = '#556';
      note.style.marginTop = '6px';
      note.textContent = 'Unggah bukti transfer (gambar). Jika Cloudinary belum dikonfigurasi, file disimpan secara lokal (dataURL).';
      proofDiv.appendChild(note);
    }
  }
  if (o.paymentProofStatus === 'rejected'){
    const rejNote = document.createElement('div');
    rejNote.style.color = '#b02';
    rejNote.style.marginTop = '6px';
    rejNote.textContent = `Bukti ditolak: ${o.paymentProofNote || 'tidak ada catatan'}`;
    proofDiv.appendChild(rejNote);
  }
  div.appendChild(proofDiv);

  // address
  const addrDiv = document.createElement('div');
  addrDiv.textContent = `Alamat: ${o.address.name} — ${o.address.phone} — ${o.address.addr}`;
  div.appendChild(addrDiv);

  // actions: jika belum dibayar dan bukan COD, pengguna bisa konfirmasi bayar (simulasi)
  const actions = document.createElement('div');
  actions.style.marginTop = '8px';
  actions.style.display = 'flex';
  actions.style.gap = '8px';

  if (o.paymentStatus === 'pending'){
    const confBtn = document.createElement('button');
    confBtn.className = 'btn-primary';
    confBtn.textContent = 'Konfirmasi Pembayaran';
    confBtn.addEventListener('click', ()=> confirmPayment(o.id));
    actions.appendChild(confBtn);
  }
  if (o.paymentStatus === 'cod_pending'){
    const codBtn = document.createElement('button');
    codBtn.className = 'btn-primary';
    codBtn.textContent = 'Tandai Lunas (COD)';
    codBtn.addEventListener('click', ()=> confirmPayment(o.id));
    actions.appendChild(codBtn);
  }

  // Admin quick toggle paid/unpaid (jika admin)
  if (isAdminUser()){
    if (o.paymentProof && o.paymentProofStatus === 'uploaded'){
      const approveBtn = document.createElement('button');
      approveBtn.className = 'btn-primary';
      approveBtn.textContent = 'Approve Bukti';
      approveBtn.addEventListener('click', ()=> adminApproveProof(o.id));
      actions.appendChild(approveBtn);

      const rejectBtn = document.createElement('button');
      rejectBtn.className = 'btn-danger';
      rejectBtn.textContent = 'Reject Bukti';
      rejectBtn.addEventListener('click', ()=> {
        const note = prompt('Alasan penolakan (opsional):') || '';
        adminRejectProof(o.id, note);
      });
      actions.appendChild(rejectBtn);
    } else {
      const adminBtn = document.createElement('button');
      adminBtn.className = 'btn-muted';
      adminBtn.textContent = (o.paymentStatus === 'paid') ? 'Tandai Belum Lunas' : 'Tandai Lunas';
      adminBtn.addEventListener('click', ()=> adminTogglePaid(o.id));
      actions.appendChild(adminBtn);
    }
  }

  div.appendChild(actions);

  wrap.appendChild(div);
  }); }

// unggah bukti pembayaran untuk pesanan saat ini (user)
async function uploadPaymentProof(orderId){
  if (!currentUser) { window.location.href = 'login.html'; return; }
  const orders = getOrdersForUser();
  const idx = orders.findIndex(o=>o.id===orderId);
  if (idx === -1) { showToast('Pesanan tidak ditemukan', 'error'); return; }
  const input = document.getElementById(`proof-file-${orderId}`);
  if (!input || !input.files || !input.files[0]) { showToast('Pilih file bukti terlebih dahulu', 'error'); return; }
  const file = input.files[0];
  try {
    showToast('Mengunggah bukti...', 'info');
    let url = '';
    if (CLOUDINARY_CLOUD_NAME && CLOUDINARY_UPLOAD_PRESET){
      url = await uploadToCloudinary(file);
    } else {
      // fallback to dataURL (demo)
      url = await fileToDataURL(file);
    }
    orders[idx].paymentProof = url;
    orders[idx].paymentProofStatus = 'uploaded';
    orders[idx].paymentProofNote = '';
    // set overall payment status to pending confirmation if currently pending
    if (orders[idx].paymentStatus === 'pending') orders[idx].paymentStatus = 'pending_confirmation';
    saveOrdersForUser(orders);
    showToast('Bukti berhasil diunggah. Menunggu konfirmasi.', 'success');
    renderOrdersPage();
  } catch(err){
    console.error(err);
    showToast('Gagal mengunggah bukti: ' + (err.message || err), 'error');
  }
}

// konfirmasi pembayaran oleh user (simulasi)
function confirmPayment(orderId){
  if (!currentUser) return;
  const orders = getOrdersForUser();
  const idx = orders.findIndex(o=>o.id===orderId);
  if (idx === -1) return;
  if (!confirm('Konfirmasi pembayaran untuk pesanan ini? (Simulasi: ini akan menandai pesanan sebagai terbayar)')) return;
  orders[idx].paymentStatus = 'paid';
  orders[idx].paymentProofStatus = orders[idx].paymentProofStatus || 'n/a';
  orders[idx].paidAt = new Date().toISOString();
  saveOrdersForUser(orders);
  showToast('Pembayaran dikonfirmasi (simulasi). Terima kasih!', 'success');
  renderOrdersPage();
}

// admin approve/reject proof
function adminApproveProof(orderId){
  if (!requireAdminAction()) return;
  const orders = getOrdersForUser();
  const idx = orders.findIndex(o=>o.id===orderId);
  if (idx === -1) return;
  if (!confirm('Setujui bukti pembayaran dan tandai pesanan sebagai LUNAS?')) return;
  orders[idx].paymentStatus = 'paid';
  orders[idx].paymentProofStatus = 'approved';
  orders[idx].paidAt = new Date().toISOString();
  saveOrdersForUser(orders);
  showToast('Bukti disetujui, pesanan ditandai LUNAS', 'success');
  renderOrdersPage();
}
function adminRejectProof(orderId, note){
  if (!requireAdminAction()) return;
  const orders = getOrdersForUser();
  const idx = orders.findIndex(o=>o.id===orderId);
  if (idx === -1) return;
  if (!confirm('Tolak bukti pembayaran?')) return;
  orders[idx].paymentProofStatus = 'rejected';
  orders[idx].paymentProofNote = note || '';
  orders[idx].paymentStatus = 'pending'; // kembali menunggu pembayaran
  saveOrdersForUser(orders);
  showToast('Bukti ditolak', 'info');
  renderOrdersPage();
}

// admin toggle paid/unpaid (simulasi)
function adminTogglePaid(orderId){
  if (!requireAdminAction()) return;
  const orders = getOrdersForUser();
  const idx = orders.findIndex(o=>o.id===orderId);
  if (idx === -1) return;
  if (orders[idx].paymentStatus === 'paid'){
    if (!confirm('Batalkan tanda lunas untuk pesanan ini?')) return;
    orders[idx].paymentStatus = 'pending';
    delete orders[idx].paidAt;
  } else {
    if (!confirm('Tandai pesanan ini sebagai sudah dibayar?')) return;
    orders[idx].paymentStatus = 'paid';
    orders[idx].paidAt = new Date().toISOString();
  }
  saveOrdersForUser(orders);
  showToast('Status pembayaran diperbarui', 'success');
  renderOrdersPage();
}

// ---------------- admin page (products & users) ----------------
function renderAdminProducts(){ if (!isManagerOrAdmin()){ showToast('Akses ditolak: hanya admin/manager', 'error'); window.location.href='index.html'; return; } const wrap = document.getElementById('admin-products'); if (!wrap) return; wrap.innerHTML = ''; getProducts().forEach(p=>{ const el = document.createElement('div'); el.className = 'admin-product'; const img = document.createElement('img'); img.src = p.image; img.alt = p.name; el.appendChild(img); const info = document.createElement('div'); info.style.flex = '1'; const title = document.createElement('div'); title.style.fontWeight = '700'; title.textContent = p.name; info.appendChild(title); const meta = document.createElement('div'); meta.textContent = `Rp${p.price.toLocaleString()} — Stok: ${p.stock}`; info.appendChild(meta); const desc = document.createElement('div'); desc.style.fontSize = '0.9em'; desc.style.color = '#556'; desc.textContent = p.description; info.appendChild(desc); el.appendChild(info); const actions = document.createElement('div'); actions.style.display='flex'; actions.style.flexDirection='column'; actions.style.gap='6px'; const editBtn = document.createElement('button'); editBtn.className='btn-primary'; editBtn.textContent='Edit'; editBtn.addEventListener('click', ()=> editProduct(p.id)); actions.appendChild(editBtn); const delBtn = document.createElement('button'); delBtn.className='btn-danger'; delBtn.textContent='Hapus'; delBtn.addEventListener('click', ()=> removeProduct(p.id)); actions.appendChild(delBtn); el.appendChild(actions); wrap.appendChild(el); }); }

function resetProductForm(){ document.getElementById('p-id').value = ''; document.getElementById('p-name').value = ''; document.getElementById('p-price').value = ''; document.getElementById('p-stock').value = ''; document.getElementById('p-desc').value = ''; document.getElementById('p-image-file').value = ''; document.getElementById('p-image-url').value = ''; }
function editProduct(id){ if (!isManagerOrAdmin()){ showToast('Akses ditolak', 'error'); return; } const p = findProduct(id); if (!p) return; document.getElementById('p-id').value = p.id; document.getElementById('p-name').value = p.name; document.getElementById('p-price').value = p.price; document.getElementById('p-stock').value = p.stock; document.getElementById('p-desc').value = p.description; document.getElementById('p-image-url').value = p.image; window.scrollTo({top:0,behavior:'smooth'}); }
function removeProduct(id){ if (!requireManagerOrAdmin()) return; if (!confirm('Hapus produk ini?')) return; deleteProduct(id); renderAdminProducts(); renderProducts(); showToast('Produk dihapus', 'success'); }

// ---------- saveProduct (MODIFIED: upload to Cloudinary if file provided) ----------
async function saveProduct(){
  if (!requireManagerOrAdmin()) return;
  const id = document.getElementById('p-id').value;
  const name = document.getElementById('p-name').value.trim();
  const price = Number(document.getElementById('p-price').value);
  const stock = Number(document.getElementById('p-stock').value);
  const desc = document.getElementById('p-desc').value.trim();
  const fileEl = document.getElementById('p-image-file');
  const urlEl = document.getElementById('p-image-url').value.trim();

  // Perbaikan validasi: izinkan price = 0, tolak negatif / NaN
  if (!name || isNaN(price) || price < 0 || isNaN(stock) || stock < 0){ showToast('Lengkapi nama, harga (>=0), stok (>=0)', 'error'); return; }

  try {
    let imgUrl = urlEl || null;
    if (fileEl && fileEl.files && fileEl.files[0]) {
      // Pastikan Cloudinary dikonfigurasi
      if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_UPLOAD_PRESET){
        showToast('Upload file memerlukan konfigurasi Cloudinary. Set CLOUDINARY_CLOUD_NAME dan CLOUDINARY_UPLOAD_PRESET di script.js', 'error');
        return;
      }
      // upload file ke Cloudinary
      imgUrl = await uploadToCloudinary(fileEl.files[0]);
    }
    if (!imgUrl) imgUrl = 'https://via.placeholder.com/600x400?text=No+Image';

    if (id){
      const prod = { id: Number(id), name, price: Number(price), stock: Number(stock), image: imgUrl, description: desc };
      updateProduct(prod);
      showToast('Produk diperbarui', 'success');
    } else {
      const prod = { name, price: Number(price), stock: Number(stock), image: imgUrl, description: desc };
      addProduct(prod);
      showToast('Produk ditambahkan', 'success');
    }
    resetProductForm(); renderAdminProducts(); renderProducts();
  } catch (err) {
    console.error(err);
    showToast('Gagal upload gambar: ' + err.message, 'error');
  }
}

// ---------------- user management (admin) ----------------
function renderAdminUsers(){ if (!requireAdminAction()) return; const wrap = document.getElementById('admin-users'); if (!wrap) return; const users = getUsers(); wrap.innerHTML = ''; const table = document.createElement('div'); table.style.display = 'flex'; table.style.flexDirection = 'column'; table.style.gap = '8px'; Object.keys(users).sort().forEach(username=>{ const u = users[username]; const role = u.role || 'user'; const row = document.createElement('div'); row.style.display = 'flex'; row.style.alignItems = 'center'; row.style.justifyContent = 'space-between'; row.style.border = '1px solid #eef4f4'; row.style.padding = '8px'; row.style.borderRadius = '8px'; const left = document.createElement('div'); left.style.display='flex'; left.style.gap='12px'; left.style.alignItems='center'; const nameDiv = document.createElement('div'); nameDiv.style.fontWeight='700'; nameDiv.textContent = username; left.appendChild(nameDiv); const roleDiv = document.createElement('div'); roleDiv.style.color='#556'; roleDiv.style.fontSize='0.95em'; roleDiv.textContent = role; left.appendChild(roleDiv); row.appendChild(left); const right = document.createElement('div'); right.style.display='flex'; right.style.gap='8px'; right.style.alignItems='center';

if (role !== 'admin'){
  const makeAdminBtn = document.createElement('button');
  makeAdminBtn.textContent = 'Make Admin';
  makeAdminBtn.addEventListener('click', ()=> setUserRole(username,'admin'));
  right.appendChild(makeAdminBtn);
} else {
  const setManagerBtn = document.createElement('button');
  setManagerBtn.textContent = 'Set Manager';
  setManagerBtn.addEventListener('click', ()=> setUserRole(username,'manager'));
  right.appendChild(setManagerBtn);
}

if (role !== 'manager'){
  const makeManagerBtn = document.createElement('button');
  makeManagerBtn.textContent = 'Make Manager';
  makeManagerBtn.addEventListener('click', ()=> setUserRole(username,'manager'));
  right.appendChild(makeManagerBtn);
} else {
  const demoteBtn = document.createElement('button');
  demoteBtn.textContent = 'Demote to User';
  demoteBtn.addEventListener('click', ()=> setUserRole(username,'user'));
  right.appendChild(demoteBtn);
}

const delBtn = document.createElement('button');
delBtn.textContent = 'Hapus';
if (username === currentUser){ delBtn.disabled = true; delBtn.style.opacity = '0.6'; delBtn.style.cursor = 'not-allowed'; }
delBtn.addEventListener('click', ()=> deleteUserAdmin(username));
right.appendChild(delBtn);

row.appendChild(right);
table.appendChild(row);
}); wrap.appendChild(table); }
function setUserRole(username, role){ if (!requireAdminAction()) return; const users = getUsers(); if (!users[username]){ showToast('User tidak ditemukan', 'error'); return; } if (users[username].role === 'admin' && role !== 'admin'){ const adminCount = Object.values(users).filter(u=>u.role==='admin').length; if (adminCount <= 1){ showToast('Tidak bisa menurunkan: minimal satu admin harus tersedia', 'error'); return; } } users[username].role = role; saveUsers(users); renderAdminUsers(); showToast(`${username} di-set role: ${role}`, 'success'); }
function deleteUserAdmin(username){ if (!requireAdminAction()) return; if (username === currentUser){ showToast('Tidak bisa menghapus akun yang sedang login', 'error'); return; } const users = getUsers(); if (!users[username]){ showToast('User tidak ditemukan', 'error'); return; } if (!confirm(`Hapus user "${username}" beserta data (keranjang & pesanan)?`)) return; delete users[username]; saveUsers(users); localStorage.removeItem(`cart_${username}`); localStorage.removeItem(`orders_${username}`); renderAdminUsers(); showToast(`User ${username} dihapus`, 'success'); }

// ---------------- users export / import ----------------
function exportUsers(){ if (!requireAdminAction()) return; const users = getUsers(); const blob = new Blob([JSON.stringify(users, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `users_${new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')}.json`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); showToast('Export users: file diunduh', 'success'); }
function importUsers(){ if (!requireAdminAction()) return; const fileInput = document.getElementById('import-users-file'); if (!fileInput || !fileInput.files || !fileInput.files[0]){ showToast('Pilih file JSON untuk import', 'error'); return; } const file = fileInput.files[0]; const mode = document.getElementById('import-mode') ? document.getElementById('import-mode').value : 'merge'; const fr = new FileReader(); fr.onload = function(e){ try { const parsed = JSON.parse(e.target.result); if (typeof parsed !== 'object'){ showToast('File tidak berisi object users valid', 'error'); return; } const existing = getUsers(); if (mode === 'replace'){ const adminCount = Object.values(parsed).filter(u => (u && (u.role==='admin' || (u.isAdmin || false) ))).length; if (adminCount === 0){ showToast('Import gagal: file tidak memiliki admin', 'error'); return; } const out = {}; Object.entries(parsed).forEach(([k,v])=>{ if (typeof v === 'string') out[k] = { password: v, role: (k==='admin' ? 'admin' : 'user') }; else if (v && typeof v === 'object'){ if (v.password && v.role) out[k] = { password: v.password, role: v.role }; else if (v.password && v.isAdmin !== undefined) out[k] = { password: v.password, role: v.isAdmin ? 'admin' : 'user' }; else if (v.password) out[k] = { password: v.password, role: 'user' }; else out[k] = { password: btoa(String(v)), role: 'user' }; } else out[k] = { password: btoa(String(v)), role: 'user' }; }); saveUsers(out); showToast('Import sukses (replace)', 'success'); } else { const merged = { ...existing }; Object.entries(parsed).forEach(([k,v])=>{ if (typeof v === 'string') merged[k] = { password: v, role: (k==='admin' ? 'admin' : 'user') }; else if (v && typeof v === 'object'){ if (v.password && v.role) merged[k] = { password: v.password, role: v.role }; else if (v.password && v.isAdmin !== undefined) merged[k] = { password: v.password, role: v.isAdmin ? 'admin' : 'user' }; else if (v.password) merged[k] = { password: v.password, role: 'user' }; else merged[k] = { password: btoa(String(v)), role: 'user' }; } else merged[k] = { password: btoa(String(v)), role: 'user' }; }); saveUsers(merged); showToast('Import sukses (merge)', 'success'); } renderAdminUsers(); } catch(err){ showToast('Error membaca file: format JSON tidak valid', 'error'); } }; fr.readAsText(file); }

// ---------------- auth: login/register/logout ----------------
// performLogin & performRegister sekarang mendukung async hash (SHA-256 base64) dan migrasi password legacy
async function performLogin(){ 
  const uEl = document.getElementById('login-username'); const pEl = document.getElementById('login-password'); const err = document.getElementById('login-error');
  if (!uEl || !pEl) return;
  const user = uEl.value.trim(), pass = pEl.value;
  if (!user || !pass){ if (err) err.textContent = 'Username / password tidak boleh kosong'; return; }
  const users = getUsers();
  const stored = users[user] && users[user].password;
  const legacy = hash(pass);
  let sha = null;
  try { sha = await asyncHash(pass); } catch(e){ sha = legacy; } // fallback

  if (stored && (stored === legacy || stored === sha)){
    // migrate to sha if needed
    if (stored !== sha){
      users[user].password = sha;
      saveUsers(users);
    }
    currentUser = user;
    localStorage.setItem('currentUser', currentUser);
    loadCartForUser();
    showToast('Login sukses', 'success');
    window.location.href='index.html';
    return;
  }
  if (err) err.textContent = 'Login gagal: username / password salah';
}

async function performRegister(){ const uEl = document.getElementById('register-username'); const pEl = document.getElementById('register-password'); const p2El = document.getElementById('register-password2'); const err = document.getElementById('register-error'); if (!uEl || !pEl || !p2El) return; const user = uEl.value.trim(), pass = pEl.value, pass2 = p2El.value; if (!user){ if (err) err.textContent='Username tidak boleh kosong'; return; } if (user.length < 3){ if (err) err.textContent='Username minimal 3 karakter'; return; } if (!pass || pass.length < 6){ if (err) err.textContent='Password minimal 6 karakter'; return; } if (pass !== pass2){ if (err) err.textContent='Konfirmasi password tidak cocok'; return; } const users = getUsers(); if (users[user]){ if (err) err.textContent='Username sudah terdaftar'; return; } const hashed = await asyncHash(pass); users[user] = { password: hashed, role: 'user' }; saveUsers(users); currentUser = user; localStorage.setItem('currentUser', currentUser); loadCartForUser(); showToast('Registrasi sukses', 'success'); window.location.href='index.html'; }

function logout(){ currentUser = null; localStorage.removeItem('currentUser'); cart = []; showToast('Logout', 'info'); window.location.href='login.html'; }

// ---------------- redirect after login (intent) ----------------
function handleRedirectAfterLogin(){ const token = localStorage.getItem('redirectAfterLogin'); if (!token) return; localStorage.removeItem('redirectAfterLogin'); if (token.startsWith('add:')){ const parts = token.split(':'); const id = parseInt(parts[1],10); const qty = parts[2] ? parseInt(parts[2],10) : 1; loadCartForUser(); const available = getAvailableStock(id); const inCart = (cart.find(i=>i.id===id)||{}).qty||0; const possible = Math.min(qty, Math.max(0, available - inCart)); if (possible <= 0) { showToast('Stok tidak mencukupi', 'error'); return; } const prod = findProduct(id); if (!prod) return; const found = cart.find(i=>i.id===id); if (found) found.qty += possible; else cart.push({...prod, qty:possible}); saveCartForUser(); updateCartUI(); showToast(`${prod.name} x${possible} ditambahkan ke keranjang`); } else if (token === 'showCart'){ const panel = document.getElementById('cart'); if (panel) panel.classList.remove('hidden'); updateCartUI(); } }

// ---------------- navigation helpers ----------------
function goAdmin(){ if (!isAdminUser()){ showToast('Akses ditolak: hanya admin', 'error'); window.location.href='index.html'; return; } window.location.href = 'admin.html'; }

// ---------------- init per page ----------------
window.addEventListener('DOMContentLoaded', ()=>{
  seedProductsIfNeeded();
  currentUser = localStorage.getItem('currentUser') || null;
  loadCartForUser();

  updateHeaderUI();

  if (document.getElementById('product-container')){
    const searchInput = document.getElementById('search-input'); if (searchInput) searchInput.addEventListener('input', renderProducts);
    const filterStock = document.getElementById('filter-stock') ? document.getElementById('filter-stock') : null; if (filterStock) filterStock.addEventListener('change', renderProducts);
    renderProducts(); handleRedirectAfterLogin();
  }

  if (document.getElementById('product-detail')){ renderProductDetail(); handleRedirectAfterLogin(); }
  if (document.getElementById('checkout-items')){ renderCheckoutItems(); }
  if (document.getElementById('orders-list')){ if (!currentUser){ window.location.href='login.html'; return; } renderOrdersPage(); }

  if (document.getElementById('admin-products')){
    if (!isManagerOrAdmin()){ showToast('Akses ditolak: hanya admin/manager', 'error'); window.location.href='index.html'; return; }
    renderAdminProducts();
    if (isAdminUser()) renderAdminUsers();
  }

  if (document.getElementById('login-username')) document.getElementById('login-username').focus();
  if (document.getElementById('register-username')) document.getElementById('register-username').focus();

  updateCartUI();
});

// Expose functions to global scope used in HTML
window.handleAddToCart = handleAddToCart;
window.addFromDetail = addFromDetail;
window.changeQty = changeQty;
window.toggleCart = function(){ const panel = document.getElementById('cart'); if (!panel) return; if (!currentUser){ localStorage.setItem('redirectAfterLogin','showCart'); window.location.href='login.html'; return; } panel.classList.toggle('hidden'); updateCartUI(); };
window.proceedToCheckout = proceedToCheckout;
window.performLogin = performLogin;
window.performRegister = performRegister;
window.placeOrder = placeOrder;
window.decreaseCartQty = decreaseCartQty;
window.increaseCartQty = increaseCartQty;
window.removeFromCart = removeFromCart;
window.saveProduct = saveProduct;
window.resetProductForm = resetProductForm;
window.editProduct = editProduct;
window.removeProduct = removeProduct;
window.goAdmin = goAdmin;
window.renderAdminUsers = renderAdminUsers;
window.setUserRole = setUserRole;
window.deleteUserAdmin = deleteUserAdmin;
window.exportUsers = exportUsers;
window.importUsers = importUsers;
window.confirmPayment = confirmPayment;
window.adminTogglePaid = adminTogglePaid;
window.adminApproveProof = adminApproveProof;
window.adminRejectProof = adminRejectProof;
window.uploadPaymentProof = uploadPaymentProof;
window.showPaymentPreview = showPaymentPreview;
