import { navigate } from '../index.js';
import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Enable2Fa extends Abstract {
    constructor(params) {
        loadCSS('../styles/Enable2Fa.css');
        super(params);
        this.setTitle("2Fa Enable");
        this.cssSelector = '../styles/Enable2Fa.css';
    }

    async getHtml() {
        return `
        <div class="container-f d-flex justify-content-center align-items-center position-relative" style="height:100vh">
        <div class="overlay"></div>    
        <div class="fa-container">
            <h1 class="big-text text-center display-4 mb-5" style="margin-top: -90px;">Enable 2FA</h1>
            <div class="qr-code">
        
            </div>
            <input type="text" class="form-control" id="2fa-code" placeholder="Enter 2FA Code" required>
            <button type="submit" class="btn btn-secondary text-center">Login</button>
        </div>

        </div>
        `;
    }

   

    initialize() {
       this.Enable2Fa();
       this.verify2Fa();
    }

    async Enable2Fa() {
        try {
            const response = await fetch('http://localhost:8001/api/auth/generate-qr/', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('tmp_access_token')}`,
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
            });
    
            if (!response.ok) {
                throw new Error('Failed to fetch QR code');
            }
    
            const data = await response.json();
            console.log(data);
    
            // Set the QR code image in the HTML
            const qrCodeDiv = document.querySelector('.qr-code');
            if (qrCodeDiv) {
                qrCodeDiv.innerHTML = `<img src="${data.qr_code}" alt="QR Code" class="qr-code-img">`;
            }
        } catch (error) {
            console.error('Error enabling 2FA:', error);
        }
    }
    

    cleanup() {
        

       
        const cssLink = document.querySelector(`link[href="${this.cssSelector}"]`);
        if (cssLink) {
            cssLink.remove();
        }

    }

    async getCsrfToken() {
        const name = 'csrftoken=';
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            cookie = cookie.trim();
            if (cookie.indexOf(name) === 0) {
                return cookie.substring(name.length);
            }
        }
        return null;
    }

    async verify2Fa(){
        document.querySelector('.btn').addEventListener('click', async () => {
            const code = document.getElementById('2fa-code').value;
        
            try {
                const csrfToken = await this.getCsrfToken();
                const response = await fetch('http://localhost:8001/api/auth/verify-2fa/', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('tmp_access_token')}`,
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken,
                    },
                    credentials: 'include',
                    body: JSON.stringify({ code }),
                });
        
                const data = await response.json();
                console.log('------------------>>>',data);
                if (response.ok) {
                    alert('2FA verified successfully!');
                    //change 2fa status to true
                    localStorage.setItem('access_token', localStorage.getItem('tmp_access_token'));
                    localStorage.setItem('refresh_token', localStorage.getItem('tmp_refresh_token'));
                    localStorage.removeItem('tmp_access_token');
                    localStorage.removeItem('tmp_refresh_token');
                    this.change2faStatus();
                    navigate('/');
                } else {
                    alert(data.error || 'Failed to verify 2FA.');
                }
            } catch (error) {
                console.error('Error verifying 2FA:', error);
            }
        });
        
    }


    async change2faStatus(){
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch('http://localhost:8001/api/auth/change-2fa-status/', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                credentials: 'include',
            });
    
            if (!response.ok) {
                throw new Error('Failed to change 2FA status');
            }
           
            const data = await response.json();
            console.log(data);
        } catch (error) {
            console.error('Error changing 2FA status:', error);
        }
    }
}
