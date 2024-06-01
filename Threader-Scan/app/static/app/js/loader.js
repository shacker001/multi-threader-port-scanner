// Function to show loader animation
function showLoader() {
    document.querySelector('.loader').style.display = 'block'; // Display the loader
    document.querySelector('.container').style.display = 'none'; // Hide the content
}

// Function to hide loader animation
function hideLoader() {
    document.querySelector('.loader').style.display = 'none'; // Hide the loader
    document.querySelector('.container').style.display = 'block'; // Display the content
}

// Show loader initially
showLoader();

// Simulate loading delay (2 seconds) and then hide loader
setTimeout(hideLoader, 2000); // Delay time (in milliseconds)

