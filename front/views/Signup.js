import { navigate } from '../index.js';
import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Signup extends Abstract {
    constructor(params) {
        loadCSS('../styles/Signup.css');
        super(params);
        this.setTitle("Signup");
        this.cssSelector = '../styles/Signup.css';
    }

    async getHtml() {
        return `
        <div class="container-f d-flex justify-content-center align-items-center position-relative" style="height:100vh">
        <div class="overlay"></div>    
        <div class="container signbg d-flex rounded flex-column justify-content-center align-items-center" style="width:500px; height:100vh">
                <h1 class="big-text text-center display-4 mb-5" style="margin-top: -150px;">Register</h1>
                <div class="form-container d-flex flex-column justify-content-center">
                    <form id="signup-form" class="container" enctype="multipart/form-data">
                        <div class="form-group mb-4">
                            <input type="text" class="form-control" id="username" placeholder="Username" required>
                        </div>
                        <div class="form-group mb-4">
                            <input type="email" class="form-control" id="email" placeholder="Email" required>
                        </div>
                        <div class="form-group mb-4">
                            <input type="password" class="form-control" id="password" placeholder="Password" required>
                        </div>
                        <div class="form-group mb-4">
                            <input type="password" class="form-control" id="confirm-password" placeholder="Confirm Password" required>
                        </div>
                        <div class="form-group mb-4">
                            <input type="file" class="form-control" id="avatar" accept="image/*">
                        </div>
                        <button id="btn-submit" type="submit" class="btn btn-secondary text-center">Submit</button>
                    </form>
                    <button id="loginIntra" class="btn btn-outline-light text-center" style="margin-top: 100px">Sign in with Intra 42</button>
                    <div class="parag">
                        <p id="login"> Already have an account? <a href="/login">Login here</a></p>
                    </div>
                </div>
            </div>
        </div>
        `;
    }

    async loginWithIntra() {
        document.getElementById('loginIntra').addEventListener('click', async () => {
            // try {
            //     // Perform the fetch request
            //     const response = await fetch('http://localhost:8001/api/auth/login42/', {
            //         method: 'GET',
            //         credentials: 'include', // Includes cookies
            //         redirect: 'follow',    // Allow the fetch to follow redirects
            //     });
    
            //     // Since the request redirects to the 42 OAuth page, check for a redirect
            //     if (response.redirected) {
            //         // Redirect the browser to the 42 login page
            //         window.location.href = response.url;
            //     } else {
            //         alert('Login failed. Please try again.');
            //     }
            // } catch (error) {
            //     console.error('Error:', error);
            //     alert('Login failed. Please try again.');
            // }

            window.location.href = 'http://localhost:8001/api/auth/login42/';
        });
    }

    initialize() {
        const form = document.getElementById('signup-form');
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
    
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const avatar = document.getElementById('avatar').files[0];
    
            if (password !== confirmPassword) {
                alert('Passwords do not match!');
                return;
            }
            if (username.length < 2 || username.length > 10) {
                alert('Username must be between 2 and 10 characters');
                return;
            }
    
            const formData = new FormData();
            formData.append('login', username);
            formData.append('email', email);
            formData.append('password', password);
            formData.append('password2', confirmPassword);
            
            // Check if the user has selected an avatar, if not, add the default one
            if (avatar) {
                formData.append('avatar', avatar);
            } else {
                // Default avatar when none is selected
                const defaultAvatar = new File([await fetch('../images/default.jpeg').then(res => res.blob())], 'default.jpeg', { type: 'image/jpeg' });
                formData.append('avatar', defaultAvatar);
            }
    
            try {
                const response = await fetch('http://localhost:8001/api/auth/register/', {
                    method: 'POST',
                    body: formData,
                    credentials: 'include',
                });
    
                if (!response.ok) {
                    throw new Error('Registration failed');
                }
    
                const data = await response.json();
                // Create custom alert
                const alertBox = document.createElement('div');
                alertBox.className = 'custom-alert';
                alertBox.innerText = 'Regisered!';
                document.body.appendChild(alertBox);
    
                // Remove the alert after 3 seconds
                setTimeout(() => {
                    alertBox.remove();
                }, 3000);
    
                navigate('/login');
            } catch (error) {
                console.error('Error:', error);
                alert('Registration failed. Please try again.');
            }
        });
        this.loginWithIntra();
    }
    

    cleanup() {
        

        // Remove the dynamically added CSS
        const cssLink = document.querySelector(`link[href="${this.cssSelector}"]`);
        if (cssLink) {
            cssLink.remove();
        }

        // If you had event listeners or timers, clear them here
        // Example: Remove event listener
        // document.querySelector('.login-link')?.removeEventListener('click', this.someHandler);

        // Clear any temporary DOM elements or states
    }
}
