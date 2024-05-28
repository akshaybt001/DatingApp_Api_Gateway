const form = document.getElementById('login-form');
const errorMessage = document.querySelector('.error-message');

form.addEventListener('submit', (event) => {
  event.preventDefault();

  const email = document.getElementById('username').value;
  const password = document.getElementById('password').value;
 // Log the request body

  // Send data to backend using fetch or XMLHttpRequest
  fetch('/user/login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email, password })  // Stringify directly in the body
  })
  .then(response => {
    console.log('Response:', response);
    return response.json();
  })
  .then(data => {
    console.log('Response data:', data);
    if (data.success) {
      // Login successful - redirect or display success message
      alert('Login successful!');
      // (Optional) Redirect to another page after successful login
      // window.location.href = '/dashboard'; // Replace with your target URL
    } else {
      errorMessage.textContent = data.message; // Set error message from backend response
    }
  })
  .catch(error => {
    console.error('Error:', error);
    errorMessage.textContent = 'An error occurred. Please try again.';
  });
});
