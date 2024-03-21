// Function to show loader
function showLoader() {
    document.querySelector('.loader').style.display = 'block';
    document.querySelector('.content').style.display = 'none';
}

// Function to hide loader
function hideLoader() {
    document.querySelector('.loader').style.display = 'none';
    document.querySelector('.content').style.display = 'block';
}

// Show loader initially
showLoader();

// Simulate loading delay and then hide loader
setTimeout(hideLoader, 2000); // Adjust delay time as needed (in milliseconds)
