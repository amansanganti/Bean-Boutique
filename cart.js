function addToCart(name, price, image){
  let cart = JSON.parse(localStorage.getItem("beanCart")) || [];

  const existing = cart.find(item => item.name === name);

  if(existing){
    existing.qty += 1;
  } else {
    cart.push({
      name: name,
      price: price,
      image: image,
      qty: 1
    });
  }

  localStorage.setItem("beanCart", JSON.stringify(cart));
  alert(name + " added to cart ☕");
}