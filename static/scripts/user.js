// Document ready event ensures that code runs after DOM is loaded
// code to remove the cookie from a logged-in user
$(document).ready(function () {

    // Setting up click event handler for elements with 'btn-logout' class
    $('.btn-logout').click(function (e) {

        // Removing 'auth-session' cookie
        Cookies.remove('auth-session');
    });
});