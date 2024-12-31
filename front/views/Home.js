import { navigate } from '../index.js';
import Abstract from './Abstract.js';
import { fetchUserData } from './authutils.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Home extends Abstract {
    constructor(params) {
        super(params);
        loadCSS('../styles/home.css');
        this.setTitle("Home");
        this.cssSelector = '../styles/home.css';
    }

    async getHtml() {
        const user = await fetchUserData('http://localhost:8001/api/auth/user/');
        // console.log('User:', user);
        // if (user.isIntraUser) {
        //     alert('intranet user');
        // }else{
        //     alert('not intranet user');
        //     // console.log('User:', user.avatar);
        // }
        // const avatarUrl = `${user.image}`;
        const avatarUrl = user.isIntraUser ? user.image : `http://localhost:8001${user.avatar}`;

        return `
        <div class="first-container">
            <div class="content">
                <nav class="navbar navbar-expand-lg " style="height:100px;">
                    <div class="navbar-nav">
                        <a class="nav-link">
                            <div class="search"></div>
                            <input type="text" id="search-input" class="search-input" placeholder="Search users...">
                            <div id="search-results" class="search-results"></div>
                        </a>
                        <div class="nav-link">
                            <p class="greeting">Hey,</p>
                            <p class="username"><strong>${user.login}</strong></p>
                        </div>
                        <a class="nav-link" href="/profile">
                            <div class="profile-img" style="background-image: url('${avatarUrl}');"></div>
                        </a>
                    </div>
                </nav>

                <div class="bodypage">
                    <div class="side-nav">
                        <div class="logo"></div>
                        <ul>
                            <li>
                                <a href="/">
                                    <img src="../images/sidenav-img/home.png" class="home">
                                    <p>Home</p>
                                </a>
                            </li>
                            <li>
                                <a href="/tournaments">
                                    <img src="../images/sidenav-img/trophy.png" class="home">
                                    <p>Tournaments</p>
                                </a>
                            </li>
                            <li>
                                <a href="/chat">
                                    <img src="../images/sidenav-img/messages.png" class="home">
                                    <p>Chat</p>
                                </a>
                            </li>
                            <li id="settings-part">
                                <a href="/settings">
                                    <img src="../images/sidenav-img/settings.png" class="home">
                                    <p>Settings</p>
                                </a>
                            </li>
                        </ul>
                        <div class="sep"></div>
                        <ul>
                            <li>
                                <a id="logout-link">
                                    <img src="../images/sidenav-img/logout.png">
                                    <p>Logout</p>
                                </a>
                            </li>
                        </ul>
                    </div>   
                </div>
            </div>
            <div class="fixed-bottom text-right p-4">
                <button id="play" click="gotoAI()" class="btn btn-outline-light">PLAY AI</button>
            </div>
        </div>
        <!-- AI or LOCAL -->
        <div id="play-form-container" class="play-form-container hidden">
            <div class="play-form">
                <div class="top-bar">
                    <h2>Select Opponent</h2>
                    <span id="close-button" class="close-icon">&times;</span>
                </div>
                <form>
                    
                    <div class="match computer-match">
                        <h3 class="first-el">COMPUTER MATCH</h3>
                        <div class="avatar-match ai"></div>
                        <button id="play-computer" type="submit" class="btn btn-outline-light second-el">Start</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- User Info Popup -->
        <div id="user-info-popup" class="user-info-popup hidden">
            <div class="user-info-content">
                <span id="popup-close" class="popup-close">&times;</span>
                <div class="user-card">
                    <div class="user-avatar" id="popup-avatar"></div>
                    <h2 id="popup-username"></h2>
                </div>
                <div class="user-actions">
                    <!-- Friend button will be inserted here --> 
                </div>
            </div>
            <h2 class="popup-title">Stats</h2>
            <div class="user-stats">
                <div class="stat">
                    <h3>Wins</h3>
                    <p id="number-of-match-wins">10</p>
                </div>
                <div class="stat">
                    <h3>Losses</h3>
                    <p id="number-of-match-losses">5</p>
                </div>
                <div class="stat">
                    <h3>Win Rate</h3>
                    <p id="win-rate">66%</p>
                </div>
            </div>
            <h2 class="popup-title">Latest Matches</h2>
            <div class="latest-matches">
                <h2 class="no-match">No Matche Played</h2>
                <div class="match" id="matches-card">
                    <ul id="all-match-cards">
                        <li>
                            <div class="match-avatar"></div>
                            <p class="match-username">User123</p>
                            <p class="match-result">2-0</p>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
        `;
    }


    
    initialize() {
        // Attach event listener for logout
        if (!localStorage.getItem('access_token')) {
            alert('You are not logged in');
            return navigate('/welcome');
            
        }

        document.getElementById('logout-link').addEventListener('click', async (event) => {
            event.preventDefault();
            await this.logoutUser();
            localStorage.removeItem('access_token');
            if (localStorage.getItem('refresh_token')) {
                localStorage.removeItem('refresh_token');
            }
            
            navigate('/welcome');
        });
    
        // Handle search input
        const searchInput = document.getElementById('search-input');
        searchInput.addEventListener('input', async (event) => {
            const searchString = event.target.value;
            if (searchString.trim()) {
                await this.searchUsers(searchString);
            } else {
                // Clear the search results if the input is empty
                document.getElementById('search-results').style.display = 'none';
            }
        });
    
        // Bind the localOrComputer logic to the Play button
        const playButton = document.getElementById('play');
        if (playButton) {
            playButton.addEventListener('click', this.gotoAI);
        }
    
       

        this.checkIsIntraUser();
        
    }

    gotoAI(){
        navigate('/training');
    }

    async checkIsIntraUser() {
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch('http://localhost:8001/api/auth/user/', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Ensure the token is passed
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });
            const data = await response.json();
            if (data.isIntraUser === true) {
                document.getElementById('settings-part').style.display = 'none';
            }else{
                document.getElementById('settings-part').style.display = 'block';
            }
        }catch(error){
            console.error('Error checking if user is intra:', error);
        }
    }
    
   
    displaySearchResults(users) {
        const searchResultsContainer = document.getElementById('search-results');
        searchResultsContainer.innerHTML = ''; // Clear previous results
        if (users.length > 0) {
            searchResultsContainer.style.display = 'block'; // Show results container
            const ul = document.createElement('ul');
            users.forEach(user => {
                const li = document.createElement('li');
                const avatarDiv = document.createElement('div');
                avatarDiv.className = 'avatar';
                const avatarUrl = user.isIntraUser ? user.image : `http://localhost:8001${user.avatar}`;
                console.log('User avatar:', avatarUrl ,' of user ', user.login);
                avatarDiv.style.backgroundImage = `url('${avatarUrl}')`;
                avatarDiv.style.backgroundSize = 'cover';
                avatarDiv.style.backgroundPosition = 'center';
                
                const usernameDiv = document.createElement('div');
                usernameDiv.className = 'username';
                usernameDiv.textContent = user.login;
    
                li.appendChild(avatarDiv);
                li.appendChild(usernameDiv);


                li.addEventListener('click', () => {
                    // console.log('User clicked:', user.id);
                    this.showUserPopup(user);
                });
                ul.appendChild(li);
            });
            searchResultsContainer.appendChild(ul);
        } else {
            searchResultsContainer.style.display = 'none'; // Hhhhhhhhide if no users found
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

    async sendFriendRequest(receiverId) {
        alert('Sending friend request...');
        try {
            const csrfToken = await this.getCsrfToken();
            console.log('CSRF Token:------>', csrfToken);
            const response = await fetch(`http://localhost:8001/api/friend/send-request/${receiverId}/`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Include token if required
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken // Include CSRF token from the cookie
                },
                credentials: 'include' // Include cookies in the request
            });
    
            if (response.ok) {
                alert('Friend request sent successfully');
                const friendButtonContainer = document.querySelector('.user-actions');
                friendButtonContainer.innerHTML = '<h2 class="request-text">Requested</h2>';
            } else {
                const errorText = await response.text();
                console.error('Error sending friend request:', errorText);
            }
        } catch (error) {
            console.error('Error during sending friend request:', error);
        }
    }
    
    
    async acceptFriendRequest(requestId) {
        // console.log('Accepting friend request with ID:', requestId);
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch(`http://localhost:8001/api/friend/accept-request/${requestId}/`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Include token if required
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken // Include CSRF token
                },
                credentials: 'include'
            });
    
            if (response.ok) {
                alert('Friend request accepted successfully');
                const friendButtonContainer = document.querySelector('.user-actions');
                friendButtonContainer.innerHTML = '<label class="">Already Friends</label>';
            } else {
                const errorText = await response.text();
                console.error('Error accepting friend request:', errorText);
            }
        } catch (error) {
            console.error('Error during accepting friend request:', error);
        }
    }
    
    async getIdOfUser() {
        try{

            const response = await fetch('http://localhost:8001/api/auth/user/', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Ensure the token is passed
                    'Content-Type': 'application/json'
                }}
            );
            const res = await response.json();
            return res;
        }catch(error){
            console.error('Error fetching user id:', error);
        }
    }

    async showUserPopup(userId) {
        
        try {
            // Fetch the user's profile information from the backend
            const response = await fetch(`http://localhost:8001/api/auth/user/${userId.id}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Ensure the token is passed
                    'Content-Type': 'application/json'
                }
            });
    
            if (!response.ok) {
                console.error('Error fetching user profile:', await response.text());
                return;
            }


            const statusResponse = await fetch(`http://localhost:8001/api/friend/check-status/${userId.id}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Ensure the token is passed
                    'Content-Type': 'application/json'
                }
            });

            if (!statusResponse.ok) {
                console.error('Error fetching user profile status:', await statusResponse.text());
                return;
            }
            
            const statusRes = await statusResponse.json();
            const user = await response.json(); // Get user data including friend status
    
            const popup = document.getElementById('user-info-popup');
            const avatarDiv = document.getElementById('popup-avatar');
            const username = document.getElementById('popup-username');
            const friendButtonContainer = document.querySelector('.user-actions');
            
            // Set avatar and username in popup
            const avatarUrl = user.isIntraUser ? user.image : `http://localhost:8001${user.avatar}`;
            console.log('User avatar: of',user.login ,' is ', avatarUrl);
            avatarDiv.style.backgroundImage = `url('${avatarUrl}')`;
            avatarDiv.style.backgroundSize = 'cover';
            avatarDiv.style.backgroundPosition = 'center';  
            username.textContent = user.login;
    
            // Clear any existing friend button content
            friendButtonContainer.innerHTML = '';
            const loggedUser = await this.getIdOfUser();
            if (userId.id === loggedUser.id) {
               
                const myProfile = document.createElement('label');
                myProfile.className = '';
                myProfile.textContent = 'My Profile';
    
                // Add unfriend functionality (optional: add event listener for unfriend)
                friendButtonContainer.appendChild(myProfile);
                
            }else if (statusRes.status === 'friends') {
                // User is already a friend, show "Unfriend" button
                const alreadyFriendLbl = document.createElement('label');
                alreadyFriendLbl.className = '';
                alreadyFriendLbl.textContent = 'Already Friends';
    
                // Add unfriend functionality (optional: add event listener for unfriend)
                friendButtonContainer.appendChild(alreadyFriendLbl);
            }else if (statusRes.status === 'request_sent'){ 
                // Friend request is already sent, show "Requested" text
                const requestText = document.createElement('h2');
                requestText.className = 'request-text';
                requestText.textContent = 'Requested';
                friendButtonContainer.appendChild(requestText);
            }else if (statusRes.status === 'request_received') {
                // Create a container for the buttons
                const buttonContainer = document.createElement('div');
                buttonContainer.className = 'friend-request-buttons';

                // Create Accept button
                const acceptButton = document.createElement('button');
                acceptButton.className = 'btn btn-outline-light accept-btn';
                acceptButton.textContent = 'Accept';

                // Create Reject button
                const rejectButton = document.createElement('button');
                rejectButton.className = 'btn btn-outline-light reject-btn';
                rejectButton.textContent = 'Reject';

                // Append buttons to the container
                buttonContainer.appendChild(acceptButton);
                buttonContainer.appendChild(rejectButton);

                // Append the container to the friend button container
                friendButtonContainer.appendChild(buttonContainer);

                // Add event listeners to the buttons
                acceptButton.addEventListener('click', () => {
                    this.acceptFriendRequest(user.id);
                });

                rejectButton.addEventListener('click', () => {
                    this.rejectFriendRequest(user.id);
                });
            }else{
                // Not friends, show "Add Friend" button
                const friendButton = document.createElement('button');
                friendButton.className = 'btn btn-outline-light friend-btn';
                friendButton.textContent = 'Add Friend';
    
                // Add event listener to send friend request
                friendButton.addEventListener('click', () => {
                    this.sendFriendRequest(user.id); // Pass the user ID
                });
    
                friendButtonContainer.appendChild(friendButton);
            }


            // console.log('status: --->', statusRes.status);

    
            popup.classList.add('show'); // Show the popup
    
            // Close popup when the close button is clicked
            document.getElementById('popup-close').addEventListener('click', () => {
                this.closeUserPopup();
            });
            this.collectmatchesofUser(userId.id);
        } catch (error) {
            console.error('Error loading user profile:', error);
        }
    }
    
    async collectmatchesofUser(userId) {
        try {
            const response = await fetch(`http://localhost:8001/api/game/allmygames/${userId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Include token if required
                    'Content-Type': 'application/json'
                },
            });
            const data = await response.json();
            // console.log('Data length:', data.length);

            const matchesCard = document.getElementById('matches-card');
            if (!matchesCard) {
                console.error('Matches card element not found in the DOM.');
                return;
            }
    
            if (data.length === 0) {
                // console.log('No matches played wa do it');
                document.querySelector('.no-match').style.display = 'block';
                document.querySelector('.no-match').style.marginTop = '120px';
                document.querySelector('.no-match').style.textAlign = 'center';
                document.getElementById('matches-card').style.display = 'none';
                document.getElementById('win-rate').textContent = '0%';
                document.getElementById('number-of-match-wins').textContent = '0';
                document.getElementById('number-of-match-losses').textContent = '0';
            } else {
                // console.log('Matches played');
                document.querySelector('.no-match').style.display = 'none';
                document.getElementById('matches-card').style.display = 'block';
                document.getElementById('number-of-match-wins').textContent = '10';
                document.getElementById('number-of-match-losses').textContent = '5';
    
                const allMatchCards = document.getElementById('all-match-cards');
                allMatchCards.innerHTML = '';
                let winningmatches = 0;
                let losingmatches = 0;
                let totalMatches = 0;
    
                for (let i = 0; i < data.length; i++) {
                    const match = data[i];
                    
                    let dataofOpponent;
    
                    if (userId === match.player_one) {
                        // console.log('match ', i, ' i am Player one');
                        dataofOpponent = await this.fetchOpponentPic(match.player_two);
                        // console.log('Opponent data: of player two', dataofOpponent);
                    } else {
                        // console.log('match ', i, ' i am Player two');
                        dataofOpponent = await this.fetchOpponentPic(match.player_one);
                        // console.log('Opponent data: of player one', dataofOpponent);
                    }
    
                    const matchCard = document.createElement('li');
                    const matchAvatar = document.createElement('div');
                    matchAvatar.className = 'match-avatar';
    
                    const matchUsername = document.createElement('p');
                    matchUsername.className = 'match-username';
                    const dataofOpponentAvatar = dataofOpponent.isIntraUser ? dataofOpponent.image : `http://localhost:8001${dataofOpponent.avatar}`;
                    matchAvatar.style.backgroundImage = `url('${dataofOpponentAvatar}')`;
                    matchUsername.textContent = dataofOpponent.login;
    
                    const matchResult = document.createElement('p');
                    matchResult.className = 'match-result';
                    matchResult.textContent = `${match.score_player_1}  -  ${match.score_player_2}`;
    
                    matchCard.appendChild(matchAvatar);
                    matchCard.appendChild(matchUsername);
                    matchCard.appendChild(matchResult);
                    allMatchCards.appendChild(matchCard);
                    if ((userId === match.player_one && match.score_player_1 > match.score_player_2) ||
                        (userId === match.player_two && match.score_player_2 > match.score_player_1)) {
                        matchCard.style.border   = '2px solid green';
                        winningmatches++;
                        totalMatches++;
                    }else{
                        matchCard.style.border   = '2px solid red';
                        losingmatches++;
                        totalMatches++;
                    }
                }
                document.getElementById('number-of-match-wins').textContent = winningmatches;
                document.getElementById('number-of-match-losses').textContent = losingmatches;
                const winRate = (winningmatches / (winningmatches + losingmatches)) * 100;
                document.getElementById('win-rate').textContent = `${winRate.toFixed(2)}%`;
            }
        } catch (error) {
            console.error('Error fetching user matches:', error);
        }
    }
    
    async rejectFriendRequest(senderId) {
        alert('Rejecting friend request...');
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch(`http://localhost:8001/api/friend/decline-request/${senderId}/`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });
    
            if (response.ok) {
                alert('Friend request rejected successfully');
                document.querySelector('.user-actions').innerHTML = '<button class="btn btn-outline-light friend-btn">Add Friend</button>';
                
            } else {
                const errorData = await response.json();
                alert(`Error: ${errorData.detail}`);
                console.error('Error rejecting friend request:', errorData);
            }
        } catch (error) {
            console.error('Error during rejecting friend request:', error);
        }
    }
    

    
    async fetchOpponentPic(userId) {
        try {
            const response = await fetch(`http://localhost:8001/api/auth/user/${userId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Include token if required
                    'Content-Type': 'application/json'

                }}
            );
            const res = await response.json();
            return res;
        }catch (error) {
            console.error('Error fetching opponent pic:', error);

        }
    }
    
    closeUserPopup() {
        const popup = document.getElementById('user-info-popup');
        popup.classList.remove('show');
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
    

    async logoutUser() {
        try {
            const csrfToken = await this.getCsrfToken();
            const accessToken = localStorage.getItem('access_token');
    
            const response = await fetch('http://localhost:8001/api/auth/logout/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}),
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });
    
            const data = await response.json();
    
            if (!response.ok) {
                throw new Error(data.detail || 'Logout failed');
            }
    
            // Clear tokens and navigate
            localStorage.removeItem('access_token');
            if (localStorage.getItem('refresh_token')) {
                localStorage.removeItem('refresh_token');
            }    
           
    
            navigate('/welcome');
    
        } catch (error) {
            console.error('Error during logout:', error);
            
            // Create error alert
            const alertBox = document.createElement('div');
            alertBox.className = 'custom-alert error';
            alertBox.innerText = error.message || 'Logout failed. Please try again.';
            document.body.appendChild(alertBox);
    
            setTimeout(() => {
                alertBox.remove();
            }, 3000);
        }
    }
    
    async searchUsers(searchString) {
        try {
            const csrfToken = await this.getCsrfToken();
            
            const response = await fetch(`http://localhost:8001/api/auth/search/?search=${encodeURIComponent(searchString)}`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Include token if required
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken // Include CSRF token
                },
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displaySearchResults(data);
            } else {
                console.error('Error fetching search results:', await response.text());
            }
        } catch (error) {
            console.error('Error during search:', error);
        }
    }
}