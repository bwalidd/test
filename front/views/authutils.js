export async function fetchUserData(url) {
    let token = localStorage.getItem('access_token');
    // console.log('Access Token:', token);

    try {
        let response = await fetch(url, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            credentials: 'include'
        });

        if (response.status === 401) {  // Token might be expired
            token = await refreshAccessToken();
            response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                credentials: 'include'
            });
        }

        if (response.ok) {
            return await response.json();
        } else {
            throw new Error('Failed to fetch user data');
        }
    } catch (error) {
        console.error('Error fetching user data:', error);
        return { image: '/path/to/default/avatar.jpg', login: 'Guest' };
    }
}

export async function refreshAccessToken() {
    try {
        const response = await fetch('http://localhost:8001/api/auth/refresh-token/', {
            method: 'POST',
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('access_token', data.access);
            return data.access;
        } else {
            throw new Error('Refresh token expired');
        }
    } catch (error) {
        console.error('Error refreshing access token:', error);
        window.location.href = '/login';
    }
}

// authutils.js

export function getCsrfToken() {
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

export async function logoutUser() {
    try {
        const csrfToken = getCsrfToken();
        const accessToken = localStorage.getItem('access_token');
        // console.log('CSRF Token:', csrfToken);
        // console.log('Access Token:', accessToken);

        const response = await fetch('http://localhost:8001/api/auth/logout/', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`, // Ensure this is correct
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken // Ensure this is correct
            },
            credentials: 'include'
        });

        if (!response.ok) {
            const errorText = await response.text(); // or response.json() if the response is JSON
            throw new Error(`Logout failed: ${errorText}`);
        }
    } catch (error) {
        console.error('Error during logout:', error);
    }
}

