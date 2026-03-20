/**
 * SECURE Cart Functions with Input Validation & XSS Prevention
 */

// Validate price is a positive number
function isValidPrice(price) {
  const priceNum = parseFloat(price);
  return !isNaN(priceNum) && priceNum > 0 && priceNum < 10000;
}

// Validate quantity
function isValidQuantity(qty) {
  const qtyNum = parseInt(qty);
  return !isNaN(qtyNum) && qtyNum > 0 && qtyNum <= 1000;
}

// Secure Add to Cart with validation
function addToCart(name, price, image){
  // Rate limiting on cart adds
  if (!checkRateLimit('cart_add', 20, 60000)) {
    alert(handleSecurityError('rateLimit'));
    return;
  }

  // Validate and sanitize inputs
  name = sanitizeInput(name);
  if (!name || name.length === 0) {
    alert(handleSecurityError('validation'));
    return;
  }

  if (!isValidPrice(price)) {
    alert(handleSecurityError('validation'));
    console.error('Invalid price:', price);
    return;
  }

  image = sanitizeInput(image);

  // Safe retrieval from storage
  let cart = safeGetStorage("beanCart") || [];
  
  // Validate cart structure
  if (!Array.isArray(cart)) {
    cart = [];
  }

  // Check if item already exists
  const existing = cart.find(item => item.name === name);

  if(existing){
    if (isValidQuantity(existing.qty + 1)) {
      existing.qty += 1;
    } else {
      alert("Maximum quantity reached for this item");
      return;
    }
  } else {
    // Create secure cart item object
    const cartItem = {
      name: sanitizeHTML(name),
      price: parseFloat(price).toFixed(2),
      image: sanitizeHTML(image),
      qty: 1,
      id: generateSecureID()
    };
    cart.push(cartItem);
  }

  // Safe storage
  const saved = safeSetStorage("beanCart", cart);
  if (saved) {
    alert(sanitizeHTML(name) + " added to cart ☕");
    updateCartCount();
  } else {
    alert("Error saving to cart. Please try again.");
  }
}

// Secure Remove from Cart
function removeFromCart(itemName) {
  if (!checkRateLimit('cart_remove', 30, 60000)) {
    alert(handleSecurityError('rateLimit'));
    return;
  }

  itemName = sanitizeInput(itemName);
  let cart = safeGetStorage("beanCart") || [];
  
  if (!Array.isArray(cart)) return;

  const index = cart.findIndex(item => item.name === itemName);
  if (index > -1) {
    cart.splice(index, 1);
    safeSetStorage("beanCart", cart);
    updateCartCount();
    loadCart(); // Refresh cart display
  }
}

// Secure Update Cart Quantity
function updateCartQuantity(itemName, newQty) {
  itemName = sanitizeInput(itemName);
  
  if (!isValidQuantity(newQty)) {
    alert(handleSecurityError('validation'));
    return;
  }

  let cart = safeGetStorage("beanCart") || [];
  const item = cart.find(i => i.name === itemName);
  
  if (item) {
    item.qty = parseInt(newQty);
    safeSetStorage("beanCart", cart);
    updateCartCount();
  }
}

// Safe Coupon Application with Rate Limiting
function applyCoupon() {
  if (!checkRateLimit('coupon_apply', 5, 60000)) { // 5 attempts per minute
    alert(handleSecurityError('rateLimit'));
    return;
  }

  const couponInput = document.getElementById("couponCode");
  let couponCode = sanitizeInput(couponInput.value.toUpperCase());

  if (!couponCode || couponCode.length === 0) {
    alert("Please enter a coupon code");
    return;
  }

  if (couponCode.length > 20) {
    alert(handleSecurityError('validation'));
    return;
  }

  // Example valid coupons (in production, validate server-side)
  const validCoupons = {
    "SAVE10": 0.10,
    "SAVE20": 0.20,
    "WELCOME": 0.10,
    "BEANLOVER": 0.15
  };

  if (validCoupons[couponCode]) {
    const discount = validCoupons[couponCode];
    safeSetStorage("appliedCoupon", {code: couponCode, discount: discount});
    alert(`✓ Coupon applied! ${(discount * 100)}% off`);
    calculateTotal();
  } else {
    alert("Invalid coupon code");
  }
}

// Safe Checkout with Validation
function secureCheckout() {
  const cart = safeGetStorage("beanCart");
  
  if (!cart || cart.length === 0) {
    alert("Your cart is empty");
    return;
  }

  const userSession = safeGetStorage("userSession");
  
  if (!userSession) {
    alert("Please sign in before checking out");
    return;
  }

  // Validate cart items one more time
  const validCart = cart.every(item => 
    isValidPrice(item.price) && isValidQuantity(item.qty)
  );

  if (!validCart) {
    alert(handleSecurityError('validation'));
    return;
  }

  // Proceed to payment (in production, connect to payment gateway)
  alert("Proceeding to secure checkout...");
}

// Clear cart safely
function clearCart() {
  localStorage.removeItem("beanCart");
  updateCartCount();
  alert("Cart cleared");
}

}