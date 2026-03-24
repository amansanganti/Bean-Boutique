// Profile Page Interactions

function switchTab(event, tabId) {
  // Remove active class from all nav items
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.remove('active');
  });

  // Remove active class from all tab panes
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.remove('active');
  });

  // Add active class to clicked nav item
  if (event && event.currentTarget) {
    event.currentTarget.classList.add('active');
  } else {
    // Fallback for initial call if needed (though overview is active by default)
    const fallbackItem = Array.from(document.querySelectorAll('.nav-item')).find(item => 
      item.getAttribute('onclick') && item.getAttribute('onclick').includes(`'${tabId}'`)
    );
    if (fallbackItem) fallbackItem.classList.add('active');
  }

  // Add active class to target tab pane
  const targetPane = document.getElementById(`${tabId}-tab`);
  if (targetPane) targetPane.classList.add('active');

  // Animate tab content
  gsap.from(targetPane, {
    opacity: 0,
    y: 15,
    duration: 0.5,
    ease: "power2.out"
  });
}

function handleLogout() {
  if (confirm("Are you sure you want to logout?")) {
    // In a real app, clear session/token here
    alert("Logged out successfully.");
    window.location.href = "index.html";
  }
}

// Optional: Handle profile image update mock
document.addEventListener('DOMContentLoaded', () => {
  const editBtn = document.querySelector('.edit-avatar');
  if (editBtn) {
    editBtn.addEventListener('click', () => {
      alert("This would open a file picker to change your avatar!");
    });
  }
  
  // Redeem button mock
  document.querySelectorAll('.redeem-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const rewardName = this.parentElement.querySelector('h4').textContent;
      if (confirm(`Do you want to redeem your points for: ${rewardName}?`)) {
        alert("Success! Reward redeemed.");
      }
    });
  });
});
