import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Settings extends Abstract {
    constructor(params) {
        loadCSS('../styles/Settings.css');
        super(params);
        this.imageRemoved = false; // Flag to track if the avatar was removed
        this.newAvatarFile = null; 
        this.setTitle("Settings");
        this.cssSelector = '../styles/Settings.css';
    }

    async getHtml() {
        return `
            <div class="bodyy">
                <div class="overlay"></div>
                <div class="settings-container">
                    <h1>User Settings</h1>
                    
                    <form class="settings-form" id="settingsForm">
                        <!-- Avatar Section -->
                        <div class="form-group avatar-group">
                            <div class="avatar-preview" id="avatarPreview" style="background-image: url('../images/default-avatar.png');"></div>
                            <input type="file" id="avatar" name="avatar" accept="image/*" onchange="uploadAvatar(event)" disabled>
                            <button type="button" id="remove-avatar" class="pic-avatar remove-avatar" onclick="removeAvatar()">Remove</button>
                            <button type="button" id="upload-avatar" class="pic-avatar upload-avatar" onclick="triggerUpload()">Upload</button>    
                        </div>

                        <!-- Username Section -->
                        <div class="form-group">
                            <label for="username">Username</label>
                            <div class="switch-container">
                                <input type="text" id="username" name="username" placeholder="Enter new username" disabled>
                                <label class="switch">
                                    <input type="checkbox" onclick="toggleInput('username')">
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>

                        <!-- Email Section -->
                        <div class="form-group">
                            <label for="email">Email</label>
                            <div class="switch-container">
                                <input type="email" id="email" name="email" placeholder="Enter new email" disabled>
                                <label class="switch">
                                    <input type="checkbox" onclick="toggleInput('email')">
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>

                        <!-- Password Section -->
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" placeholder="Enter new password">                
                        </div>
                        <div class="form-group">
                            <label for="confirmPassword">Confirm Password</label>
                            <input type="password" id="confirmPassword" name="confirmPassword" placeholder="Confirm new password">                
                        </div>
                        
                        <!-- 2FA Section -->
                        <div class="form-group two-fa" id="two-fa">
                            <label for="2fa">Two-Factor</label>
                            <button type="button" id="disable-2fa-button">Disable</button>
                           <label id="disabled-label">Disabled</label>
                        </div>

                        <!-- Save Button -->
                        <button type="button" id="saveSettingsButton" class="save-button" onclick="saveSettings()">Save Changes</button>
                    </form>
                    <div class="back-home">
                        <a href="/">Back to Home</a>
                    </div>
                </div>
            </div>
        `;
    }

    async initialize() {
        // console.log('Settings page initialized');

        window.toggleInput = this.toggleInput.bind(this);
        window.saveSettings = this.saveSettings.bind(this);
        window.removeAvatar = this.removeAvatar.bind(this);
        window.uploadAvatar = (event) => this.uploadAvatar(event);
        window.triggerUpload = this.triggerUpload.bind(this);
        await this.fetchUserData();
        this.disable2fa();
    }

    async disable2fa() {
        document.getElementById('disable-2fa-button').addEventListener('click', async () => {
            try {
                const csrfToken = await this.getCsrfToken();
                console.log('csrf--->', csrfToken);
                const response = await fetch(`http://localhost:8001/api/auth/disable-2fa/`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    }
                });
                if (response.ok) {
                    const data = await response.json();
                    console.log('2FA disabled:', data);
                    document.getElementById('disable-2fa-button').style.display = 'none';
                    document.getElementById('disabled-label').style.display = 'block';
                } else {
                    alert('Failed to disable 2FA');
                }
            } catch (error) {
                console.error('Error disabling 2FA:', error);
            }
        });
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

    async fetchUserData() {
        const csrfToken = await this.getCsrfToken();
        // console.log('csrfff--->', csrfToken);
        try {
            const response = await fetch(`http://localhost:8001/api/auth/userdetails`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                }
            });
            if (!response.ok) throw new Error(`Failed to fetch user data: ${response.statusText}`);
        
            const userData = await response.json();
            // console.log('User data:', userData);

            // Populate the fields with user data
            document.getElementById("username").value = userData.login || "";
            document.getElementById("email").value = userData.email || "";

            // Set avatar image if available
            const avatarPreview = document.getElementById("avatarPreview");
            console.log('avatar--->', userData);
            if (userData.avatar) {
                avatarPreview.style.backgroundImage = `url(http://localhost:8001${userData.avatar})`;
                avatarPreview.style.backgroundSize = "cover";
                avatarPreview.style.backgroundPosition = "center";
            }
            if (userData.mfa_enabled) {
                document.getElementById('disable-2fa-button').style.display = 'block';
                document.getElementById('disabled-label').style.display = 'none';
            }else{
                document.getElementById('disable-2fa-button').style.display = 'none';
                document.getElementById('disabled-label').style.display = 'block';
                document.getElementById('two-fa').style.marginTop = '20px';
                document.getElementById('two-fa').style.marginBottom = '20px';
            }
        } catch (error) {
            console.error('Error fetching user data:', error);
        }
    }

    toggleInput(inputId) {
        const inputField = document.getElementById(inputId);
        inputField.disabled = !inputField.disabled;
        if (inputField.disabled === false) {
            inputField.style.color = 'antiquewhite';
        } else {
            inputField.style.color = 'grey';
        }
    }

    async saveSettings() {
        const csrfToken = await this.getCsrfToken();
        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const avatar = document.getElementById('avatar').files[0];

        // Validate passwords
        if (password && password !== confirmPassword) {
            alert('Passwords do not match');
            return;
        }
        if (username.length < 2 || username.length > 10) {
            alert('Username must be between 2 and 10 characters');
            return;
        }

        const formData = new FormData();

        // Append avatar based on the `avatarRemoved` flag
        if (this.imageRemoved) {
            // Fetch default avatar as a Blob and append to formData
            const defaultAvatarBlob = await fetch('../images/default.jpeg').then(res => res.blob());
            formData.append('avatar', defaultAvatarBlob, 'default-avatar.jpeg');
        } else if (avatar) {
            formData.append('avatar', avatar);
        }

        formData.append('login', username);
        formData.append('email', email);
        if (password) {
            formData.append('password', password);
            formData.append('confirm_password', confirmPassword);
        }

        try {
            const response = await fetch(`http://localhost:8001/api/auth/user/update/`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'X-CSRFToken': csrfToken,
                },
                credentials: 'include',
                body: formData
            });
            if (!response.ok) throw new Error(`Failed to update user settings: ${response.statusText}`);
        
            const updatedData = await response.json();
            console.log('Updated user data:', updatedData);

            // Handle success
            alert('Settings updated successfully!');
        } catch (error) {
            console.error('Error updating user settings:', error);
            alert('Failed to update settings. Please try again later.');
        }
    }
    
    async removeAvatar() {
        const avatarPreview = document.getElementById("avatarPreview");
        avatarPreview.style.backgroundImage = 'url("../images/default.jpeg")';
        avatarPreview.style.backgroundSize = "cover";
        avatarPreview.style.backgroundPosition = "center";
        document.getElementById('remove-avatar').style.display = 'none';
        document.getElementById('upload-avatar').style.display = 'block';
        document.getElementById('avatar').disabled = false; // Enable the file input
        this.imageRemoved = true;
        this.newAvatarFile = null;
    }
    
    

    triggerUpload() {
        console.log("Upload button clicked, opening file input...");
        document.getElementById('avatar').click();
    }
    
    async uploadAvatar(event) {
        console.log('Uploading avatar...');
        if (event && event.target && event.target.files && event.target.files.length > 0) {
            const file = event.target.files[0];
            console.log("File selected:", file);
            const avatarPreview = document.getElementById("avatarPreview");
            avatarPreview.style.backgroundImage = `url(${URL.createObjectURL(file)})`;
            avatarPreview.style.backgroundSize = "cover";
            avatarPreview.style.backgroundPosition = "center";
    
            this.newAvatarFile = file;
            this.imageRemoved = false;
    
            document.getElementById('remove-avatar').style.display = 'block';
            document.getElementById('upload-avatar').style.display = 'none';
        } else {
            console.warn("No file selected or invalid event.");
        }
    }
    
    cleanup() {
        const cssLink = document.querySelector(`link[href="${this.cssSelector}"]`);
        if (cssLink) {
            cssLink.remove();
        }
    }
    
}
