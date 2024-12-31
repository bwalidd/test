import { navigate } from '../index.js';
import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Login extends Abstract {
    constructor(params) {
        loadCSS('../styles/Login.css');
        super(params);
        this.setTitle("Login");
        this.cssSelector = '../styles/Login.css';
    }

    async getHtml() {
        return `
        <div class="container-f d-flex justify-content-center align-items-center position-relative" style="height:100vh">
            <div class="overlay"></div>    
            <div class="container signbg d-flex rounded flex-column justify-content-center align-items-center" style="width:500px; height:100vh">
                <h1 class="big-text text-center display-4 mb-5" style="margin-top: -90px;">Login</h1>
                <div class="form-container d-flex flex-column justify-content-center">
                    <form class="container" id="login-form">
                        <div class="form-group mb-4">
                            <input type="email" class="form-control" id="email" placeholder="Email" required>
                        </div>
                        <div class="form-group mb-4">
                            <input type="password" class="form-control" id="password" placeholder="Password" required>
                        </div>
                        <button type="submit" class="btn btn-secondary text-center">Submit</button>
                    </form>
                    <div class="parag">
                        <p id="login">Don't have an account? <a href="/signup">Sign Up here</a></p>
                    </div>
                    <div id="error-message" class="text-danger mt-3"></div>
                </div>
            </div>
        </div>
        `;
    }

    initialize() {
        
        const form = document.getElementById('login-form');
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
    
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
    
            try {
                const response = await fetch('http://localhost:8001/api/auth/login/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        email: email,
                        password: password
                    })
                });
    
                if (response.ok) {
                    const data = await response.json();
                    console.log('------------------------');
                    console.log(data);
                    console.log('------------------------');
                    if (data.alwaysDisable2fa){
                        localStorage.setItem('access_token', data.access_token);
                        localStorage.setItem('refresh_token', data.refresh_token);
                        navigate('/');
                    }else{
                        if (data.isIntraUser === false && data.mfa_enabled === false){
                            localStorage.setItem('tmp_access_token', data.access_token);
                            localStorage.setItem('tmp_refresh_token', data.refresh_token);
                            navigate('/enable2fa');
                        }
                        else if(data.isIntraUser === false && data.mfa_enabled === true){
                            localStorage.setItem('tmp_access_token', data.access_token);
                            localStorage.setItem('tmp_refresh_token', data.refresh_token);
                            navigate('/login2fa');
                        }
                    }
                    
                } else {
                    const errorData = await response.json();
                    document.getElementById('error-message').innerText = errorData.detail || 'Login failed. Please try again.';
                }
            } catch (error) {
                console.error('Error:', error);
                document.getElementById('error-message').innerText = 'Login failed. Please try again.';
            }
        });
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


